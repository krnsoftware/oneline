#!/usr/bin/ruby
# -*- coding: utf-8 -*-

# One-time authentication setup for oneline.
# Target: Ruby 1.8.7 compatible syntax.
#
# Before opening this CGI, create private/setup.key containing a random secret
# (24+ characters recommended). Enter that same secret in the form below.
# The key file is deleted after successful setup. Delete setup.cgi as well.

ENV['TZ'] = 'Asia/Tokyo'
$KCODE = 'u' if RUBY_VERSION < '1.9'
if defined?(Encoding)
  Encoding.default_external = Encoding::UTF_8
  Encoding.default_internal = Encoding::UTF_8
end
STDOUT.binmode if STDOUT.respond_to?(:binmode)

require File.join(File.dirname(__FILE__), 'oneline_http')
require 'fileutils'
require 'openssl'

ROOT_DIR = File.dirname(__FILE__)
PRIVATE_DIR = File.expand_path('private', ROOT_DIR)
AUTH_FILE = File.join(PRIVATE_DIR, 'auth.conf')
SETUP_KEY_FILE = File.join(PRIVATE_DIR, 'setup.key')
ITERATIONS = 100000

FileUtils.mkdir_p(PRIVATE_DIR)
begin
  File.chmod(0700, PRIVATE_DIR)
rescue
end


def param(cgi, name)
  values = cgi.params[name]
  return '' if !values || values.empty?
  values[0].to_s
end


def h(text)
  OnelineHTTP.html_escape(text.to_s)
end


def random_bytes(length)
  begin
    return OpenSSL::Random.random_bytes(length)
  rescue
    File.open('/dev/urandom', 'rb') { |file| return file.read(length) }
  end
end


def password_digest(password, salt_hex, iterations)
  salt = [salt_hex].pack('H*')
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(password.to_s, salt, iterations.to_i, 32)
  key.unpack('H*')[0]
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


def load_setup_key
  return '' if !File.exist?(SETUP_KEY_FILE)
  begin
    key = File.read(SETUP_KEY_FILE).to_s.strip
    File.chmod(0600, SETUP_KEY_FILE) rescue nil
    key
  rescue
    ''
  end
end


def print_header(cgi)
  print cgi.header(
    'type' => 'text/html',
    'charset' => 'utf-8',
    'Cache-Control' => 'no-store',
    'Referrer-Policy' => 'no-referrer',
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY'
  )
end


def render(cgi, message, error)
  print_header(cgi)
  message_html = message.to_s.empty? ? '' : '<div class="auth-message">' + h(message) + '</div>'
  error_html = error.to_s.empty? ? '' : '<div class="auth-error">' + h(error) + '</div>'

  print <<HTML
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>oneline setup</title>
<link rel="stylesheet" href="style.css?v=0.1.1">
</head>
<body>
<main class="auth-main">
  <section class="auth-box">
    #{message_html}
    #{error_html}
    <form method="post" action="" autocomplete="off">
      <div class="auth-row">
        <label for="setup_key">setup key</label>
        <input id="setup_key" type="password" name="setup_key" autocomplete="off">
      </div>
      <div class="auth-row">
        <label for="username">name</label>
        <input id="username" type="text" name="username" autocomplete="username" autofocus>
      </div>
      <div class="auth-row">
        <label for="password">password</label>
        <input id="password" type="password" name="password" autocomplete="new-password">
      </div>
      <div class="auth-row">
        <label for="password2">again</label>
        <input id="password2" type="password" name="password2" autocomplete="new-password">
      </div>
      <div class="auth-submit"><button type="submit">設定</button></div>
    </form>
  </section>
</main>
</body>
</html>
HTML
end

cgi = OnelineCGI.new

if File.exist?(AUTH_FILE)
  render(cgi, '認証設定はすでに存在します。setup.cgi は削除してください。', '')
  exit
end

expected_key = load_setup_key
if expected_key.empty?
  render(cgi, '', 'private/setup.key がありません。24文字以上のランダムな文字列を1行だけ保存してから再度開いてください。')
  exit
end

if expected_key.length < 24
  render(cgi, '', 'private/setup.key は24文字以上にしてください。')
  exit
end

if ENV['REQUEST_METHOD'].to_s.upcase != 'POST'
  render(cgi, 'private/setup.key の内容と、最初のログイン情報を入力します。', '')
  exit
end

setup_key = param(cgi, 'setup_key')
username = param(cgi, 'username').to_s.strip
password = param(cgi, 'password')
password2 = param(cgi, 'password2')

if !secure_compare(setup_key, expected_key)
  sleep 1
  render(cgi, '', 'setup key が違います。')
  exit
end

if username.empty?
  render(cgi, '', 'name を入力してください。')
  exit
end

if password.length < 8
  render(cgi, '', 'password は8文字以上にしてください。')
  exit
end

if password != password2
  render(cgi, '', 'password が一致しません。')
  exit
end

begin
  salt_hex = random_bytes(16).unpack('H*')[0]
  digest = password_digest(password, salt_hex, ITERATIONS)
  auth_id = random_bytes(16).unpack('H*')[0]

  File.open(AUTH_FILE, File::WRONLY | File::CREAT | File::EXCL, 0600) do |file|
    file.write("username=" + username + "\n")
    file.write("algorithm=pbkdf2-hmac-sha1\n")
    file.write("iterations=" + ITERATIONS.to_s + "\n")
    file.write("salt=" + salt_hex + "\n")
    file.write("password_hash=" + digest + "\n")
    file.write("auth_id=" + auth_id + "\n")
  end
  begin
    File.chmod(0600, AUTH_FILE)
  rescue
  end
  begin
    File.delete(SETUP_KEY_FILE)
  rescue
  end

  render(cgi, '設定しました。setup key は破棄しました。setup.cgi を削除して index.cgi を開いてください。', '')
rescue Exception => e
  render(cgi, '', '設定に失敗しました: ' + e.class.to_s + ' ' + e.message.to_s)
end
