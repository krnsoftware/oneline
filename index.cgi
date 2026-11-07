#!/usr/bin/ruby
# -*- coding: utf-8 -*-

# oneline single-line memo CGI.
# Target: Ruby 1.8.7 compatible syntax.
# Authentication: single user + form login + file-backed session cookie.

ENV['TZ'] = 'Asia/Tokyo'
$KCODE = 'u' if RUBY_VERSION < '1.9'
if defined?(Encoding)
  Encoding.default_external = Encoding::UTF_8
  Encoding.default_internal = Encoding::UTF_8
end
STDOUT.binmode if STDOUT.respond_to?(:binmode)

require File.join(File.dirname(__FILE__), 'oneline_http')
require 'digest/sha1'
require 'digest/sha2'
require 'fileutils'
require 'openssl'

ROOT_DIR = File.dirname(__FILE__)
DATA_DIR = File.expand_path('data', ROOT_DIR)
PRIVATE_DIR = File.expand_path('private', ROOT_DIR)
SESSION_DIR = File.join(PRIVATE_DIR, 'sessions')
AUTH_FILE = File.join(PRIVATE_DIR, 'auth.conf')
EDIT_DIR = File.expand_path('edits', ROOT_DIR)
EDIT_FILE = File.join(EDIT_DIR, 'edits.txt')

DEFAULT_LIMIT = 100
MAX_LIMIT = 500
SESSION_DAYS = 90
SESSION_LIFETIME = SESSION_DAYS * 24 * 60 * 60
COOKIE_NAME = 'oneline_session'

FileUtils.mkdir_p(DATA_DIR)
FileUtils.mkdir_p(PRIVATE_DIR)
FileUtils.mkdir_p(SESSION_DIR)
FileUtils.mkdir_p(EDIT_DIR)

begin
  File.chmod(0700, PRIVATE_DIR)
  File.chmod(0700, SESSION_DIR)
rescue
end


def param(cgi, name)
  values = cgi.params[name]
  return '' if !values || values.empty?
  values[0].to_s
end


def one_line(text)
  text.to_s.gsub(/\r\n|\r|\n|\t/, ' ').strip
end


def h(text)
  OnelineHTTP.html_escape(text.to_s)
end


def rfc3339_now
  now = Time.now
  zone = now.strftime('%z')
  if zone && zone.length == 5
    zone = zone[0, 3] + ':' + zone[3, 2]
  end
  now.strftime('%Y-%m-%dT%H:%M:%S') + zone.to_s
end


def random_bytes(length)
  begin
    return OpenSSL::Random.random_bytes(length)
  rescue
    File.open('/dev/urandom', 'rb') { |file| return file.read(length) }
  end
end


def random_hex(length)
  random_bytes(length).unpack('H*')[0]
end


def secure_compare(a, b)
  a = a.to_s
  b = b.to_s
  return false if a.length != b.length
  result = 0
  i = 0
  while i < a.length
    result |= a[i, 1].unpack('C')[0] ^ b[i, 1].unpack('C')[0]
    i += 1
  end
  result == 0
end


def parse_key_value_file(path)
  values = {}
  return values if !File.exist?(path)

  File.open(path, 'r') do |file|
    file.each_line do |line|
      line = line.strip
      next if line.empty? || line[0, 1] == '#'
      key, value = line.split('=', 2)
      next if !key || !value
      values[key.strip] = value.strip
    end
  end
  values
end


def password_digest(password, salt_hex, iterations)
  salt = [salt_hex].pack('H*')
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password.to_s, salt, iterations.to_i, 32)
  key.unpack('H*')[0]
end


def auth_config
  parse_key_value_file(AUTH_FILE)
end


def auth_configured?
  config = auth_config
  !config['username'].to_s.empty? &&
    !config['salt'].to_s.empty? &&
    config['iterations'].to_i > 0 &&
    !config['password_hash'].to_s.empty? &&
    !config['auth_id'].to_s.empty?
end


def valid_login?(username, password)
  config = auth_config
  return false if config.empty?
  return false if !secure_compare(username.to_s, config['username'].to_s)

  begin
    actual = password_digest(password, config['salt'], config['iterations'])
  rescue
    return false
  end
  secure_compare(actual, config['password_hash'])
end


def cookie_values
  result = {}
  ENV['HTTP_COOKIE'].to_s.split(/;\s*/).each do |pair|
    key, value = pair.split('=', 2)
    next if !key || !value
    result[key] = value
  end
  result
end


def cookie_path
  script = ENV['SCRIPT_NAME'].to_s
  return '/' if script.empty? || script[0, 1] != '/'
  slash = script.rindex('/')
  return '/' if !slash || slash == 0
  script[0..slash]
end


def session_file(token)
  digest = Digest::SHA256.hexdigest(token.to_s)
  File.join(SESSION_DIR, digest + '.session')
end


def cleanup_sessions
  now = Time.now.to_i
  Dir.glob(File.join(SESSION_DIR, '*.session')).each do |path|
    begin
      expires = File.read(path).to_i
      File.delete(path) if expires <= now
    rescue
    end
  end
end


def create_session
  cleanup_sessions
  token = random_hex(32)
  expires = Time.now.to_i + SESSION_LIFETIME
  path = session_file(token)

  config = auth_config
  auth_id = config['auth_id'].to_s

  File.open(path, 'w', 0600) do |file|
    file.flock(File::LOCK_EX)
    file.write(expires.to_s + "\n")
    file.write(auth_id + "\n")
    file.flush
  end
  begin
    File.chmod(0600, path)
  rescue
  end

  [token, expires]
end


def valid_session?(token)
  return false if token.to_s.empty?
  path = session_file(token)
  return false if !File.exist?(path)

  begin
    lines = File.readlines(path)
    expires = lines[0].to_i
    stored_auth_id = lines[1].to_s.strip
    current_auth_id = auth_config['auth_id'].to_s
    if current_auth_id.empty? || !secure_compare(stored_auth_id, current_auth_id)
      File.delete(path) rescue nil
      return false
    end
    if expires <= Time.now.to_i
      File.delete(path) rescue nil
      return false
    end
    true
  rescue
    false
  end
end


def destroy_session(token)
  return if token.to_s.empty?
  path = session_file(token)
  File.delete(path) if File.exist?(path)
rescue
end


def session_token
  cookie_values[COOKIE_NAME].to_s
end


def set_cookie_header(token, expires_at)
  expires = Time.at(expires_at).gmtime.strftime('%a, %d %b %Y %H:%M:%S GMT')
  [
    COOKIE_NAME + '=' + token.to_s,
    'Path=' + cookie_path,
    'Max-Age=' + SESSION_LIFETIME.to_s,
    'Expires=' + expires,
    'Secure',
    'HttpOnly',
    'SameSite=Lax'
  ].join('; ')
end


def clear_cookie_header
  [
    COOKIE_NAME + '=',
    'Path=' + cookie_path,
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'Secure',
    'HttpOnly',
    'SameSite=Lax'
  ].join('; ')
end


def redirect_with_cookie(cgi, location, cookie)
  print "Status: 303 See Other\r\n"
  print 'Location: ' + location + "\r\n"
  print 'Set-Cookie: ' + cookie + "\r\n"
  print "Content-Type: text/html; charset=utf-8\r\n"
  print "Cache-Control: no-store\r\n"
  print "Referrer-Policy: no-referrer\r\n\r\n"
end


def redirect(cgi, location)
  print cgi.header(
    'status' => '303 See Other',
    'location' => location,
    'type' => 'text/html',
    'charset' => 'utf-8',
    'Cache-Control' => 'no-store',
    'Referrer-Policy' => 'no-referrer'
  )
end


def print_html_header(cgi)
  print cgi.header(
    'type' => 'text/html',
    'charset' => 'utf-8',
    'Cache-Control' => 'no-store',
    'Referrer-Policy' => 'no-referrer',
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY'
  )
end


def print_login_page(cgi, error_message)
  print_html_header(cgi)
  error_html = error_message.to_s.empty? ? '' : '<div class="auth-error">' + h(error_message) + '</div>'

  print <<HTML
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>oneline login</title>
<link rel="stylesheet" href="style.css?v=0.1.1">
</head>
<body>
<main class="auth-main">
  <section class="auth-box">
    <form method="post" action="" autocomplete="on">
      <input type="hidden" name="action" value="login">
      <div class="auth-row">
        <label for="username">name</label>
        <input id="username" type="text" name="username" autocomplete="username" autofocus>
      </div>
      <div class="auth-row">
        <label for="password">password</label>
        <input id="password" type="password" name="password" autocomplete="current-password">
      </div>
      #{error_html}
      <div class="auth-submit"><button type="submit">login</button></div>
    </form>
  </section>
</main>
<script>
(function () {
  function findMemo(node) {
    while (node && node !== document.body) {
      if (node.classList && node.classList.contains('memo')) return node;
      node = node.parentNode;
    }
    return null;
  }

  document.addEventListener('click', function (event) {
    var button = event.target;
    var mode = button && button.getAttribute ? button.getAttribute('data-toggle') : null;
    if (!mode) return;

    var memo = findMemo(button);
    if (!memo) return;

    var editPanel = memo.querySelector('.edit-panel');
    var historyPanel = memo.querySelector('.history-panel');
    var tools = memo.querySelector('.memo-tools');

    if (mode === 'edit') {
      if (!editPanel) return;
      var show = editPanel.hasAttribute('hidden');
      if (show) {
        editPanel.removeAttribute('hidden');
        historyPanel.setAttribute('hidden', 'hidden');
        var input = editPanel.querySelector('input[name="memo"]');
        if (input) { input.focus(); input.select(); }
      } else {
        editPanel.setAttribute('hidden', 'hidden');
      }
    } else if (mode === 'history') {
      if (!historyPanel) return;
      var showHistory = historyPanel.hasAttribute('hidden');
      if (showHistory) {
        historyPanel.removeAttribute('hidden');
        editPanel.setAttribute('hidden', 'hidden');
      } else {
        historyPanel.setAttribute('hidden', 'hidden');
      }
    }

    if (tools) tools.removeAttribute('open');
  }, false);
}());
</script>
</body>
</html>
HTML
end


def print_setup_needed(cgi)
  print_html_header(cgi)
  print <<HTML
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>oneline setup</title>
<link rel="stylesheet" href="style.css?v=0.1.1">
</head>
<body>
<main class="auth-main">
  <section class="auth-box">
    <div class="auth-message">認証設定がありません。setup.cgi で初期設定してください。</div>
  </section>
</main>
<script>
(function () {
  function findMemo(node) {
    while (node && node !== document.body) {
      if (node.classList && node.classList.contains('memo')) return node;
      node = node.parentNode;
    }
    return null;
  }

  document.addEventListener('click', function (event) {
    var button = event.target;
    var mode = button && button.getAttribute ? button.getAttribute('data-toggle') : null;
    if (!mode) return;

    var memo = findMemo(button);
    if (!memo) return;

    var editPanel = memo.querySelector('.edit-panel');
    var historyPanel = memo.querySelector('.history-panel');
    var tools = memo.querySelector('.memo-tools');

    if (mode === 'edit') {
      if (!editPanel) return;
      var show = editPanel.hasAttribute('hidden');
      if (show) {
        editPanel.removeAttribute('hidden');
        historyPanel.setAttribute('hidden', 'hidden');
        var input = editPanel.querySelector('input[name="memo"]');
        if (input) { input.focus(); input.select(); }
      } else {
        editPanel.setAttribute('hidden', 'hidden');
      }
    } else if (mode === 'history') {
      if (!historyPanel) return;
      var showHistory = historyPanel.hasAttribute('hidden');
      if (showHistory) {
        historyPanel.removeAttribute('hidden');
        editPanel.setAttribute('hidden', 'hidden');
      } else {
        historyPanel.setAttribute('hidden', 'hidden');
      }
    }

    if (tools) tools.removeAttribute('open');
  }, false);
}());
</script>
</body>
</html>
HTML
end


def new_id
  seed = [Time.now.to_f, Process.pid, rand, ENV['REMOTE_ADDR'], random_hex(8)].join(':')
  Digest::SHA1.hexdigest(seed)[0, 16]
end


def valid_memo_id?(id)
  id.to_s =~ /\A[0-9a-f]{16}\z/ ? true : false
end


def month_path
  File.join(DATA_DIR, Time.now.strftime('%Y-%m') + '.txt')
end


def append_memo(body)
  timestamp = rfc3339_now
  id = new_id
  line = [timestamp, id, body].join("\t") + "\n"

  path = month_path
  File.open(path, 'a') do |file|
    file.flock(File::LOCK_EX)
    file.write(line)
    file.flush
  end
  begin
    File.chmod(0600, path)
  rescue
  end

  id
end


def append_edit_event(id, action, body)
  return false if !valid_memo_id?(id)
  return false if action != 'E' && action != 'D' && action != 'R'
  timestamp = rfc3339_now
  line = [timestamp, id, action, body.to_s].join("\t") + "\n"

  File.open(EDIT_FILE, 'a') do |file|
    file.flock(File::LOCK_EX)
    file.write(line)
    file.flush
  end
  begin
    File.chmod(0600, EDIT_FILE)
  rescue
  end
  true
end


def append_edit(id, body)
  append_edit_event(id, 'E', body)
end


def append_delete(id)
  append_edit_event(id, 'D', '')
end


def append_restore(id)
  append_edit_event(id, 'R', '')
end


def parse_line(line)
  fields = line.chomp.split("\t", 3)
  return nil if fields.length < 3
  {
    'time' => fields[0],
    'id'   => fields[1],
    'body' => fields[2]
  }
end


def parse_edit_line(line)
  fields = line.chomp.split("\t", 4)
  return nil if fields.length < 3
  return nil if !valid_memo_id?(fields[1])
  return nil if fields[2] != 'E' && fields[2] != 'D' && fields[2] != 'R'
  {
    'time'   => fields[0],
    'id'     => fields[1],
    'action' => fields[2],
    'body'   => fields[3].to_s
  }
end


def load_edits
  latest = {}
  history = {}
  return [latest, history] if !File.exist?(EDIT_FILE)

  lines = []
  File.open(EDIT_FILE, 'r') do |file|
    file.flock(File::LOCK_SH)
    lines = file.readlines
  end

  lines.each do |line|
    edit = parse_edit_line(line)
    next if edit.nil?
    history[edit['id']] ||= []
    history[edit['id']] << edit
    latest[edit['id']] = edit
  end

  [latest, history]
end


def memo_deleted?(id)
  latest, history = load_edits
  deleted = false
  (history[id] || []).each do |event|
    deleted = true if event['action'] == 'D'
    deleted = false if event['action'] == 'R'
  end
  deleted
end


def find_memo_by_id(id)
  return nil if !valid_memo_id?(id)
  Dir.glob(File.join(DATA_DIR, '*.txt')).sort.reverse.each do |path|
    lines = []
    File.open(path, 'r') do |file|
      file.flock(File::LOCK_SH)
      lines = file.readlines
    end
    lines.reverse_each do |line|
      memo = parse_line(line)
      next if memo.nil?
      return memo if memo['id'] == id
    end
  end
  nil
end


def search_words(query)
  query.to_s.strip.split(/[,\s]+/).reject { |word| word.empty? }
end


def text_matches_words?(text, words)
  return true if words.empty?
  haystack = text.to_s.downcase
  words.each do |word|
    return false if haystack.index(word.downcase).nil?
  end
  true
end


def load_memos(query, limit, include_history, show_deleted, offset)
  words = search_words(query)
  latest, history = load_edits
  result = []
  matched_count = 0
  offset = 0 if offset.to_i < 0
  offset = offset.to_i

  Dir.glob(File.join(DATA_DIR, '*.txt')).sort.reverse.each do |path|
    lines = []
    File.open(path, 'r') do |file|
      file.flock(File::LOCK_SH)
      lines = file.readlines
    end

    lines.reverse_each do |line|
      memo = parse_line(line)
      next if memo.nil?

      memo['original_body'] = memo['body']
      memo['history'] = history[memo['id']] || []
      memo['deleted'] = false

      current_body = memo['body']
      deleted = false
      memo['history'].each do |event|
        if event['action'] == 'E'
          current_body = event['body']
        elsif event['action'] == 'D'
          deleted = true
        elsif event['action'] == 'R'
          deleted = false
        end
      end
      memo['body'] = current_body
      memo['deleted'] = deleted

      current_event = latest[memo['id']]
      memo['edited_time'] = current_event['time'] if current_event

      # Normally hide deleted memos.  When show_deleted is enabled,
      # keep them in their original chronological position alongside live memos.
      next if memo['deleted'] && !show_deleted

      # Deleted memos have no searchable current body.
      # show_deleted controls visibility only; their former text is searched
      # only when include_history ("修正前も検索") is enabled.
      if words.empty?
        current_match = true
      else
        # Search both the current memo body and its creation date/time.
        # Include the raw RFC3339 timestamp and the displayed DCS-style form
        # so queries such as 2026-10-31, 2026/10/31, 10/31, and 21:14 work.
        searchable_current = [
          memo['body'],
          memo['time'],
          display_time_inline(memo['time'])
        ].join(' ')
        current_match = !memo['deleted'] && text_matches_words?(searchable_current, words)
      end
      historical_match = false

      if !current_match && include_history && !words.empty?
        if text_matches_words?(memo['original_body'], words)
          historical_match = true
        else
          memo['history'].each do |event|
            next if event['action'] != 'E'
            if text_matches_words?(event['body'], words)
              historical_match = true
              break
            end
          end
        end
      end

      next if !current_match && !historical_match
      memo['historical_match'] = historical_match

      if matched_count < offset
        matched_count += 1
        next
      end
      matched_count += 1
      result << memo
      return result if result.length >= limit
    end
  end

  result
end

def linkify(text)
  result = ''
  rest = text.to_s
  url_re = %r{https?://[^\s<>"']+}

  while match = url_re.match(rest)
    result << h(rest[0...match.begin(0)])
    url = match[0]
    result << '<a href="' + h(url) + '" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">' + h(url) + '</a>'
    rest = rest[match.end(0)..-1].to_s
  end

  result << h(rest)
  result
end


def display_time(timestamp)
  if timestamp =~ /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/
    "#{$1}-#{$2}-#{$3} #{$4}:#{$5}"
  else
    timestamp
  end
end


def display_time_inline(timestamp)
  if timestamp =~ /\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/
    "#{$1}/#{$2}/#{$3} #{$4}:#{$5}:#{$6}"
  else
    timestamp
  end
end


def print_fragment_header(count, has_more, status)
  print "Status: " + status.to_s + "\r\n" if status && !status.to_s.empty?
  print "Content-Type: text/html; charset=utf-8\r\n"
  print "Cache-Control: no-store\r\n"
  print "Referrer-Policy: no-referrer\r\n"
  print "X-Content-Type-Options: nosniff\r\n"
  print "X-Oneline-Count: " + count.to_i.to_s + "\r\n"
  print "X-Oneline-Has-More: " + (has_more ? '1' : '0') + "\r\n\r\n"
end


def print_ajax_error(status, message)
  print "Status: " + status.to_s + "\r\n"
  print "Content-Type: text/plain; charset=utf-8\r\n"
  print "Cache-Control: no-store\r\n"
  print "Referrer-Policy: no-referrer\r\n\r\n"
  print message.to_s
end


def prepare_new_memo(memo)
  return nil if memo.nil?
  memo['original_body'] = memo['body']
  memo['history'] = []
  memo['deleted'] = false
  memo['edited_time'] = nil
  memo['historical_match'] = false
  memo
end


def render_memo_fragment(memo, query, include_history, show_deleted)
  out = ''
  memo_id = h(memo['id'])
  edit_count = memo['history'].length

  if query.empty?
    out << '<div class="memo memo-normal' + (memo['deleted'] ? ' memo-deleted' : '') + '" id="m-' + memo_id + '" data-memo-id="' + memo_id + '">'
    out << '<div class="memo-main-line">'
    if memo['deleted']
      out << '<span class="deleted-badge">削除済み</span>'
      out << '<span class="body deleted-body">' + linkify(memo['body']) + '</span>'
    else
      out << '<span class="body">' + linkify(memo['body']) + '</span>'
    end
    out << '<span class="time-inline">(' + h(display_time_inline(memo['time'])) + ')</span>'
    out << '<details class="memo-tools"><summary aria-label="操作">…</summary>'
    out << '<div class="memo-menu">'
    out << '<button type="button" data-toggle="edit">修正</button>' if !memo['deleted']
    if edit_count > 0
      out << '<button type="button" data-toggle="history">履歴 ' + edit_count.to_s + '</button>'
    else
      out << '<button type="button" data-toggle="history">履歴</button>'
    end
    if !memo['deleted']
      out << '<form method="post" action="" class="delete-form" onsubmit="return confirm(\'このメモを削除します。原文と履歴は保存されます。\');">'
      out << '<input type="hidden" name="action" value="delete">'
      out << '<input type="hidden" name="id" value="' + memo_id + '">'
      out << '<input type="hidden" name="return_q" value="' + h(query) + '">'
      out << '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      out << '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
      out << '<button type="submit" class="delete-button">削除</button></form>'
    else
      out << '<form method="post" action="" class="restore-form">'
      out << '<input type="hidden" name="action" value="restore">'
      out << '<input type="hidden" name="id" value="' + memo_id + '">'
      out << '<input type="hidden" name="return_q" value="' + h(query) + '">'
      out << '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      out << '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
      out << '<button type="submit" class="restore-button">復活</button></form>'
    end
    out << '</div></details>'
    out << '</div>'
  else
    out << '<div class="memo memo-search' + (memo['deleted'] ? ' memo-deleted' : '') + '" id="m-' + memo_id + '" data-memo-id="' + memo_id + '">'
    out << '<div class="time">' + h(display_time(memo['time'])) + '</div>'
    out << '<div class="search-body-wrap">'
    if memo['deleted']
      out << '<span class="deleted-badge">削除済み</span>'
      out << '<span class="body deleted-body">' + linkify(memo['body']) + '</span>'
    else
      out << '<span class="body">' + linkify(memo['body']) + '</span>'
      out << '<span class="history-match">過去の内容にも一致</span>' if memo['historical_match']
    end
    out << '<details class="memo-tools"><summary aria-label="操作">…</summary>'
    out << '<div class="memo-menu">'
    out << '<button type="button" data-toggle="edit">修正</button>' if !memo['deleted']
    if edit_count > 0
      out << '<button type="button" data-toggle="history">履歴 ' + edit_count.to_s + '</button>'
    else
      out << '<button type="button" data-toggle="history">履歴</button>'
    end
    if !memo['deleted']
      out << '<form method="post" action="" class="delete-form" onsubmit="return confirm(\'このメモを削除します。原文と履歴は保存されます。\');">'
      out << '<input type="hidden" name="action" value="delete">'
      out << '<input type="hidden" name="id" value="' + memo_id + '">'
      out << '<input type="hidden" name="return_q" value="' + h(query) + '">'
      out << '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      out << '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
      out << '<button type="submit" class="delete-button">削除</button></form>'
    else
      out << '<form method="post" action="" class="restore-form">'
      out << '<input type="hidden" name="action" value="restore">'
      out << '<input type="hidden" name="id" value="' + memo_id + '">'
      out << '<input type="hidden" name="return_q" value="' + h(query) + '">'
      out << '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      out << '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
      out << '<button type="submit" class="restore-button">復活</button></form>'
    end
    out << '</div></details></div>'
  end

  if !memo['deleted']
    out << '<div class="edit-panel" hidden>'
    out << '<form method="post" action="" class="inline-edit-form">'
    out << '<input type="hidden" name="action" value="edit">'
    out << '<input type="hidden" name="id" value="' + memo_id + '">'
    out << '<input type="hidden" name="return_q" value="' + h(query) + '">'
    out << '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
    out << '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
    out << '<input type="text" name="memo" maxlength="4096" autocomplete="off" value="' + h(memo['body']) + '">'
    out << '<button type="submit">保存</button>'
    out << '<button type="button" class="cancel-edit" data-toggle="edit">キャンセル</button>'
    out << '</form></div>'
  else
    out << '<div class="edit-panel" hidden></div>'
  end

  out << '<div class="history-panel" hidden>'
  if edit_count == 0
    out << '<div class="history-empty">修正履歴はありません。</div>'
  else
    versions = []
    current_version_body = memo['original_body']
    versions << { 'time' => memo['time'], 'body' => current_version_body, 'label' => '作成', 'action' => 'C' }
    memo['history'].each do |event|
      if event['action'] == 'D'
        versions << { 'time' => event['time'], 'body' => '', 'label' => '削除', 'action' => 'D' }
      elsif event['action'] == 'R'
        versions << { 'time' => event['time'], 'body' => current_version_body, 'label' => '復活', 'action' => 'R' }
      else
        current_version_body = event['body']
        versions << { 'time' => event['time'], 'body' => current_version_body, 'label' => '修正', 'action' => 'E' }
      end
    end
    versions.reverse.each_with_index do |version, index|
      current_label = (index == 0 ? ' current' : '')
      out << '<div class="history-entry' + current_label + '">'
      out << '<span class="history-time">' + h(display_time_inline(version['time'])) + '</span>'
      if index == 0 && version['action'] != 'D' && version['action'] != 'R'
        label = '現在'
      else
        label = version['label']
      end
      out << '<span class="history-label">' + h(label) + '</span>'
      if version['action'] == 'D'
        out << '<span class="history-body history-deleted">削除済み</span>'
      else
        out << '<span class="history-body">' + linkify(version['body']) + '</span>'
      end
      out << '</div>'
    end
  end
  out << '</div>'
  out << '</div>'
  out
end

cgi = OnelineCGI.new
method = ENV['REQUEST_METHOD'].to_s.upcase
action = one_line(param(cgi, 'action'))
script_location = ENV['SCRIPT_NAME'].to_s
script_location = './' if script_location.empty?

if !auth_configured?
  print_setup_needed(cgi)
  exit
end

if method == 'POST' && action == 'login'
  username = one_line(param(cgi, 'username'))
  password = param(cgi, 'password')

  if valid_login?(username, password)
    token, expires = create_session
    redirect_with_cookie(cgi, script_location, set_cookie_header(token, expires))
    exit
  else
    sleep 1
    print_login_page(cgi, 'name または password が違います。')
    exit
  end
end

token = session_token
fragment_request = (one_line(param(cgi, 'partial')) == '1' || (method == 'POST' && action == 'add_ajax'))

if !valid_session?(token)
  if fragment_request
    print_ajax_error('401 Unauthorized', 'login required')
  else
    print_login_page(cgi, '')
  end
  exit
end

if method == 'POST' && action == 'logout'
  destroy_session(token)
  redirect_with_cookie(cgi, script_location, clear_cookie_header)
  exit
end

if method == 'POST' && action == 'add_ajax'
  body = one_line(param(cgi, 'memo'))
  if body.empty?
    print_ajax_error('422 Unprocessable Entity', 'empty memo')
    exit
  end

  added_id = append_memo(body)
  ajax_query = one_line(param(cgi, 'q'))
  ajax_history = (one_line(param(cgi, 'history')) == '1')
  ajax_show_deleted = (one_line(param(cgi, 'show_deleted')) == '1' || one_line(param(cgi, 'deleted_only')) == '1')

  # Render the new memo only when it belongs in the list currently on screen.
  # This keeps both the visible list and the infinite-scroll offset consistent
  # even when posting while a search/filter is active.
  candidate = load_memos(ajax_query, 1, ajax_history, ajax_show_deleted, 0)
  memo = (!candidate.empty? && candidate[0]['id'] == added_id) ? candidate[0] : nil
  html = memo.nil? ? '' : render_memo_fragment(memo, ajax_query, ajax_history, ajax_show_deleted)

  print_fragment_header(memo.nil? ? 0 : 1, false, '201 Created')
  print html
  exit
end

if method == 'POST' && action == 'add'
  body = one_line(param(cgi, 'memo'))
  added_id = nil
  added_id = append_memo(body) if !body.empty?

  if !added_id.nil? && valid_memo_id?(added_id)
    redirect(cgi, script_location + '?added=' + OnelineHTTP.url_encode(added_id) + '#m-' + added_id)
  else
    redirect(cgi, script_location)
  end
  exit
end

if method == 'POST' && action == 'edit'
  memo_id = one_line(param(cgi, 'id'))
  body = one_line(param(cgi, 'memo'))
  return_q = one_line(param(cgi, 'return_q'))
  return_history = one_line(param(cgi, 'return_history'))
  return_show_deleted = one_line(param(cgi, 'return_show_deleted'))

  if valid_memo_id?(memo_id) && !body.empty? && !find_memo_by_id(memo_id).nil? && !memo_deleted?(memo_id)
    append_edit(memo_id, body)
  end

  location = script_location
  parts = []
  parts << 'q=' + OnelineHTTP.url_encode(return_q) if !return_q.empty?
  parts << 'history=1' if return_history == '1'
  parts << 'show_deleted=1' if return_show_deleted == '1'
  location += '?' + parts.join('&') if !parts.empty?
  location += '#m-' + memo_id if valid_memo_id?(memo_id)
  redirect(cgi, location)
  exit
end

if method == 'POST' && action == 'delete'
  memo_id = one_line(param(cgi, 'id'))
  return_q = one_line(param(cgi, 'return_q'))
  return_history = one_line(param(cgi, 'return_history'))
  return_show_deleted = one_line(param(cgi, 'return_show_deleted'))
  deleted_now = false

  if valid_memo_id?(memo_id) && !find_memo_by_id(memo_id).nil? && !memo_deleted?(memo_id)
    deleted_now = append_delete(memo_id)
  end

  location = script_location
  parts = []
  parts << 'q=' + OnelineHTTP.url_encode(return_q) if !return_q.empty?
  parts << 'history=1' if return_history == '1'
  parts << 'show_deleted=1' if return_show_deleted == '1'
  parts << 'deleted=' + OnelineHTTP.url_encode(memo_id) if deleted_now
  location += '?' + parts.join('&') if !parts.empty?
  redirect(cgi, location)
  exit
end

if method == 'POST' && action == 'restore'
  memo_id = one_line(param(cgi, 'id'))
  return_q = one_line(param(cgi, 'return_q'))
  return_history = one_line(param(cgi, 'return_history'))
  return_show_deleted = one_line(param(cgi, 'return_show_deleted'))

  if valid_memo_id?(memo_id) && !find_memo_by_id(memo_id).nil? && memo_deleted?(memo_id)
    append_restore(memo_id)
  end

  location = script_location
  parts = []
  parts << 'q=' + OnelineHTTP.url_encode(return_q) if !return_q.empty?
  parts << 'history=1' if return_history == '1'
  parts << 'show_deleted=1' if return_show_deleted == '1'
  location += '?' + parts.join('&') if !parts.empty?
  location += '#m-' + memo_id if valid_memo_id?(memo_id)
  redirect(cgi, location)
  exit
end

if method == 'POST'
  redirect(cgi, script_location)
  exit
end

query = one_line(param(cgi, 'q'))
include_history = (one_line(param(cgi, 'history')) == '1')
show_deleted = (one_line(param(cgi, 'show_deleted')) == '1' || one_line(param(cgi, 'deleted_only')) == '1')
deleted_id = one_line(param(cgi, 'deleted'))
added_id = one_line(param(cgi, 'added'))
added_now = valid_memo_id?(added_id)
show_undo = valid_memo_id?(deleted_id) && !find_memo_by_id(deleted_id).nil? && memo_deleted?(deleted_id)

if one_line(param(cgi, 'partial')) == '1'
  offset = param(cgi, 'offset').to_i
  offset = 0 if offset < 0
  page = load_memos(query, DEFAULT_LIMIT + 1, include_history, show_deleted, offset)
  has_more = page.length > DEFAULT_LIMIT
  memos = has_more ? page[0, DEFAULT_LIMIT] : page
  print_fragment_header(memos.length, has_more, '')
  memos.each do |memo|
    print render_memo_fragment(memo, query, include_history, show_deleted)
  end
  exit
end

page = load_memos(query, DEFAULT_LIMIT + 1, include_history, show_deleted, 0)
has_more = page.length > DEFAULT_LIMIT
memos = has_more ? page[0, DEFAULT_LIMIT] : page
search_active = (!query.empty? || include_history || show_deleted)
memo_autofocus = (!search_active && !added_now) ? ' autofocus' : ''
search_autofocus = search_active ? ' autofocus' : ''
added_scroll_script = ''
if added_now
  added_scroll_script = <<ADDED_SCROLL_JS
(function () {
  function showAddedMemo() {
    var memo = document.getElementById('m-#{h(added_id)}');
    var input = document.getElementById('memo-input');
    if (!memo) return;

    if (memo.scrollIntoView) {
      try {
        memo.scrollIntoView({block: 'center'});
      } catch (e) {
        memo.scrollIntoView();
      }
    }

    if (input) {
      window.setTimeout(function () {
        var x = window.pageXOffset || 0;
        var y = window.pageYOffset || 0;
        try {
          input.focus({preventScroll: true});
        } catch (e) {
          input.focus();
          window.scrollTo(x, y);
        }
      }, 20);
    }
  }

  if (window.requestAnimationFrame) {
    window.requestAnimationFrame(function () {
      window.setTimeout(showAddedMemo, 20);
    });
  } else {
    window.setTimeout(showAddedMemo, 20);
  }
}());
ADDED_SCROLL_JS
end
search_select_script = ''
if search_active
  search_select_script = <<'SEARCH_SELECT_JS'
(function () {
  function selectSearchText() {
    var input = document.getElementById('search-q');
    if (!input) return;
    input.focus();
    try {
      input.select();
      if (input.setSelectionRange) {
        input.setSelectionRange(0, input.value.length);
      }
    } catch (e) {
    }
  }

  /* Safari can move the caret after autofocus has run.
     Select again after page layout/load has settled. */
  if (window.requestAnimationFrame) {
    window.requestAnimationFrame(function () {
      window.setTimeout(selectSearchText, 30);
    });
  } else {
    window.setTimeout(selectSearchText, 30);
  }

  window.addEventListener('pageshow', function () {
    window.setTimeout(selectSearchText, 30);
  }, false);
}());
SEARCH_SELECT_JS
end

print_html_header(cgi)

print <<HTML
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>oneline</title>
<link rel="stylesheet" href="style.css?v=0.1.1">
</head>
<body>
<main id="app" data-search-active="#{search_active ? '1' : '0'}">
  <div class="compose">
    <form id="compose-form" method="post" action="">
      <input type="hidden" name="action" value="add">
      <div class="row">
        <input id="memo-input" type="text" name="memo" maxlength="4096" autocomplete="off" autocapitalize="sentences" placeholder="1行メモ"#{memo_autofocus}>
        <button type="submit">Post</button>
      </div>
    </form>
  </div>

  <div class="utility-line">
    <details class="find-panel"#{search_active ? ' open' : ''}>
      <summary>find</summary>
      <form method="get" action="" class="search">
        <div class="find-row">
          <input id="search-q" type="search" name="q" value="#{h(query)}" autocomplete="off" placeholder="Find (AND)"#{search_autofocus}>
          <button type="submit">Go</button>
        </div>
        <div class="find-options">
          <label class="history-search"><input type="checkbox" name="history" value="1" onchange="this.form.submit()"#{include_history ? ' checked' : ''}>revisions</label>
          <label class="history-search"><input type="checkbox" name="show_deleted" value="1" onchange="this.form.submit()"#{show_deleted ? ' checked' : ''}>deleted</label>
          #{query.empty? && !include_history && !show_deleted ? '' : '<a href="?">clear</a>'}
        </div>
      </form>
    </details>
  </div>

  <div class="summary-line">
    <div class="summary" id="memo-summary" data-suffix="#{query.empty? ? '' : ' / ' + h(query)}">#{memos.length}件#{query.empty? ? '' : ' / ' + h(query)}</div>
    <form method="post" action="" class="logout-form">
      <input type="hidden" name="action" value="logout">
      <button type="submit" class="logout-button">logout</button>
    </form>
  </div>
#{show_undo ? '  <div class="undo-delete">削除しました。<form method="post" action="" class="restore-form"><input type="hidden" name="action" value="restore"><input type="hidden" name="id" value="' + h(deleted_id) + '"><input type="hidden" name="return_q" value="' + h(query) + '"><input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '"><input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '"><button type="submit" class="restore-button">元に戻す</button></form></div>' : ''}
  <div class="memo-list">
HTML

if memos.empty?
  print '<div class="empty">該当するメモはありません。</div>'
else
  memos.each do |memo|
    memo_id = h(memo['id'])
    edit_count = memo['history'].length

    if query.empty?
      print '<div class="memo memo-normal' + (memo['deleted'] ? ' memo-deleted' : '') + '" id="m-' + memo_id + '" data-memo-id="' + memo_id + '">' 
      print '<div class="memo-main-line">'
      if memo['deleted']
        print '<span class="deleted-badge">削除済み</span>'
        print '<span class="body deleted-body">' + linkify(memo['body']) + '</span>'
      else
        print '<span class="body">' + linkify(memo['body']) + '</span>'
      end
      print '<span class="time-inline">(' + h(display_time_inline(memo['time'])) + ')</span>'
      print '<details class="memo-tools"><summary aria-label="操作">…</summary>'
      print '<div class="memo-menu">'
      if !memo['deleted']
        print '<button type="button" data-toggle="edit">修正</button>'
      end
      if edit_count > 0
        print '<button type="button" data-toggle="history">履歴 ' + edit_count.to_s + '</button>'
      else
        print '<button type="button" data-toggle="history">履歴</button>'
      end
      if !memo['deleted']
        print '<form method="post" action="" class="delete-form" onsubmit="return confirm(\'このメモを削除します。原文と履歴は保存されます。\');">'
        print '<input type="hidden" name="action" value="delete">'
        print '<input type="hidden" name="id" value="' + memo_id + '">'
        print '<input type="hidden" name="return_q" value="' + h(query) + '">'
        print '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
        print '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
        print '<button type="submit" class="delete-button">削除</button></form>'
      else
        print '<form method="post" action="" class="restore-form">'
        print '<input type="hidden" name="action" value="restore">'
        print '<input type="hidden" name="id" value="' + memo_id + '">'
        print '<input type="hidden" name="return_q" value="' + h(query) + '">'
        print '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
        print '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
        print '<button type="submit" class="restore-button">復活</button></form>'
      end
      print '</div></details>'
      print '</div>'
    else
      print '<div class="memo memo-search' + (memo['deleted'] ? ' memo-deleted' : '') + '" id="m-' + memo_id + '" data-memo-id="' + memo_id + '">' 
      print '<div class="time">' + h(display_time(memo['time'])) + '</div>'
      print '<div class="search-body-wrap">'
      if memo['deleted']
        print '<span class="deleted-badge">削除済み</span>'
        print '<span class="body deleted-body">' + linkify(memo['body']) + '</span>'
      else
        print '<span class="body">' + linkify(memo['body']) + '</span>'
        print '<span class="history-match">過去の内容にも一致</span>' if memo['historical_match']
      end
      print '<details class="memo-tools"><summary aria-label="操作">…</summary>'
      print '<div class="memo-menu">'
      if !memo['deleted']
        print '<button type="button" data-toggle="edit">修正</button>'
      end
      if edit_count > 0
        print '<button type="button" data-toggle="history">履歴 ' + edit_count.to_s + '</button>'
      else
        print '<button type="button" data-toggle="history">履歴</button>'
      end
      if !memo['deleted']
        print '<form method="post" action="" class="delete-form" onsubmit="return confirm(\'このメモを削除します。原文と履歴は保存されます。\');">'
        print '<input type="hidden" name="action" value="delete">'
        print '<input type="hidden" name="id" value="' + memo_id + '">'
        print '<input type="hidden" name="return_q" value="' + h(query) + '">'
        print '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      print '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
        print '<button type="submit" class="delete-button">削除</button></form>'
      else
        print '<form method="post" action="" class="restore-form">'
        print '<input type="hidden" name="action" value="restore">'
        print '<input type="hidden" name="id" value="' + memo_id + '">'
        print '<input type="hidden" name="return_q" value="' + h(query) + '">'
        print '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      print '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
        print '<button type="submit" class="restore-button">復活</button></form>'
      end
      print '</div></details></div>'
    end

    if !memo['deleted']
      print '<div class="edit-panel" hidden>'
      print '<form method="post" action="" class="inline-edit-form">'
      print '<input type="hidden" name="action" value="edit">'
      print '<input type="hidden" name="id" value="' + memo_id + '">'
      print '<input type="hidden" name="return_q" value="' + h(query) + '">'
      print '<input type="hidden" name="return_history" value="' + (include_history ? '1' : '0') + '">'
      print '<input type="hidden" name="return_show_deleted" value="' + (show_deleted ? '1' : '0') + '">'
      print '<input type="text" name="memo" maxlength="4096" autocomplete="off" value="' + h(memo['body']) + '">'
      print '<button type="submit">保存</button>'
      print '<button type="button" class="cancel-edit" data-toggle="edit">キャンセル</button>'
      print '</form></div>'
    else
      print '<div class="edit-panel" hidden></div>'
    end

    print '<div class="history-panel" hidden>'
    if edit_count == 0
      print '<div class="history-empty">修正履歴はありません。</div>'
    else
      versions = []
      current_version_body = memo['original_body']
      versions << { 'time' => memo['time'], 'body' => current_version_body, 'label' => '作成', 'action' => 'C' }
      memo['history'].each do |event|
        if event['action'] == 'D'
          versions << { 'time' => event['time'], 'body' => '', 'label' => '削除', 'action' => 'D' }
        elsif event['action'] == 'R'
          versions << { 'time' => event['time'], 'body' => current_version_body, 'label' => '復活', 'action' => 'R' }
        else
          current_version_body = event['body']
          versions << { 'time' => event['time'], 'body' => current_version_body, 'label' => '修正', 'action' => 'E' }
        end
      end
      versions.reverse.each_with_index do |version, index|
        current_label = (index == 0 ? ' current' : '')
        print '<div class="history-entry' + current_label + '">' 
        print '<span class="history-time">' + h(display_time_inline(version['time'])) + '</span>'
        if index == 0 && version['action'] != 'D' && version['action'] != 'R'
          label = '現在'
        else
          label = version['label']
        end
        print '<span class="history-label">' + h(label) + '</span>'
        if version['action'] == 'D'
          print '<span class="history-body history-deleted">削除済み</span>'
        else
          print '<span class="history-body">' + linkify(version['body']) + '</span>'
        end
        print '</div>'
      end
    end
    print '</div>'
    print '</div>'
  end
end

print <<HTML
  </div>
  <div id="scroll-sentinel" class="scroll-sentinel" data-has-more="#{has_more ? '1' : '0'}"#{has_more ? '' : ' hidden'}></div>
</main>
<script>
#{added_scroll_script}
#{search_select_script}
(function () {
  var app = document.getElementById('app');
  var composeForm = document.getElementById('compose-form');
  var memoInput = document.getElementById('memo-input');
  var memoList = document.querySelector('.memo-list');
  var summary = document.getElementById('memo-summary');
  var sentinel = document.getElementById('scroll-sentinel');
  var searchActive = app && app.getAttribute('data-search-active') === '1';
  var loadedCount = memoList ? memoList.querySelectorAll('.memo').length : 0;
  var loadingMore = false;
  var hasMore = sentinel && sentinel.getAttribute('data-has-more') === '1';

  function updateSummary() {
    if (!summary) return;
    var suffix = summary.getAttribute('data-suffix') || '';
    summary.textContent = loadedCount + '件' + suffix;
  }

  function focusMemoInput() {
    if (!memoInput) return;
    try {
      memoInput.focus({preventScroll: true});
    } catch (e) {
      var x = window.pageXOffset || 0;
      var y = window.pageYOffset || 0;
      memoInput.focus();
      window.scrollTo(x, y);
    }
  }

  if (composeForm && memoInput && memoList && window.XMLHttpRequest) {
    composeForm.addEventListener('submit', function (event) {
      var body = memoInput.value.replace(/[\\r\\n\\t]+/g, ' ').replace(/^\\s+|\\s+$/g, '');
      if (!body) {
        event.preventDefault();
        focusMemoInput();
        return;
      }
      if (composeForm.getAttribute('data-posting') === '1') {
        event.preventDefault();
        return;
      }

      event.preventDefault();
      composeForm.setAttribute('data-posting', '1');
      var button = composeForm.querySelector('button[type="submit"]');
      if (button) button.disabled = true;

      var xhr = new XMLHttpRequest();
      xhr.open('POST', composeForm.getAttribute('action') || window.location.pathname, true);
      xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
      xhr.onreadystatechange = function () {
        if (xhr.readyState !== 4) return;
        composeForm.removeAttribute('data-posting');
        if (button) button.disabled = false;

        if (xhr.status === 201) {
          var empty = memoList.querySelector('.empty');
          if (empty && empty.parentNode) empty.parentNode.removeChild(empty);
          if (xhr.responseText) {
            memoList.insertAdjacentHTML('afterbegin', xhr.responseText);
            loadedCount += 1;
            updateSummary();
          }
          memoInput.value = '';
          focusMemoInput();
        } else if (xhr.status === 401) {
          window.location.reload();
        } else {
          alert('Post failed (' + xhr.status + ')');
          focusMemoInput();
        }
      };
      var currentQuery = window.location.search ? window.location.search.substring(1) : '';
      var postBody = 'action=add_ajax&memo=' + encodeURIComponent(body);
      if (currentQuery) postBody += '&' + currentQuery;
      xhr.send(postBody);
    }, false);
  }

  function loadMore() {
    if (!hasMore || loadingMore || !memoList || !sentinel) return;
    loadingMore = true;

    var url = window.location.pathname + window.location.search;
    url += (url.indexOf('?') >= 0 ? '&' : '?') + 'partial=1&offset=' + loadedCount;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.onreadystatechange = function () {
      if (xhr.readyState !== 4) return;
      loadingMore = false;

      if (xhr.status === 200) {
        var count = parseInt(xhr.getResponseHeader('X-Oneline-Count') || '0', 10);
        hasMore = xhr.getResponseHeader('X-Oneline-Has-More') === '1';
        if (xhr.responseText) memoList.insertAdjacentHTML('beforeend', xhr.responseText);
        if (!isNaN(count)) loadedCount += count;
        updateSummary();
        sentinel.setAttribute('data-has-more', hasMore ? '1' : '0');
        if (!hasMore) sentinel.setAttribute('hidden', 'hidden');
      } else if (xhr.status === 401) {
        window.location.reload();
      }
    };
    xhr.send(null);
  }

  if (sentinel && hasMore) {
    if ('IntersectionObserver' in window) {
      var observer = new IntersectionObserver(function (entries) {
        if (entries && entries[0] && entries[0].isIntersecting) loadMore();
      }, {root: null, rootMargin: '600px 0px 600px 0px', threshold: 0});
      observer.observe(sentinel);
    } else {
      window.addEventListener('scroll', function () {
        var bottom = window.pageYOffset + window.innerHeight;
        var height = document.documentElement.scrollHeight || document.body.scrollHeight;
        if (height - bottom < 600) loadMore();
      }, false);
    }
  }
}());

(function () {
  function findMemo(node) {
    while (node && node !== document.body) {
      if (node.classList && node.classList.contains('memo')) return node;
      node = node.parentNode;
    }
    return null;
  }

  document.addEventListener('click', function (event) {
    var button = event.target;
    var mode = button && button.getAttribute ? button.getAttribute('data-toggle') : null;
    if (!mode) return;

    var memo = findMemo(button);
    if (!memo) return;

    var editPanel = memo.querySelector('.edit-panel');
    var historyPanel = memo.querySelector('.history-panel');
    var tools = memo.querySelector('.memo-tools');

    if (mode === 'edit') {
      if (!editPanel) return;
      var show = editPanel.hasAttribute('hidden');
      if (show) {
        editPanel.removeAttribute('hidden');
        historyPanel.setAttribute('hidden', 'hidden');
        var input = editPanel.querySelector('input[name="memo"]');
        if (input) { input.focus(); input.select(); }
      } else {
        editPanel.setAttribute('hidden', 'hidden');
      }
    } else if (mode === 'history') {
      if (!historyPanel) return;
      var showHistory = historyPanel.hasAttribute('hidden');
      if (showHistory) {
        historyPanel.removeAttribute('hidden');
        editPanel.setAttribute('hidden', 'hidden');
      } else {
        historyPanel.setAttribute('hidden', 'hidden');
      }
    }

    if (tools) tools.removeAttribute('open');
  }, false);
}());
</script>
</body>
</html>
HTML
