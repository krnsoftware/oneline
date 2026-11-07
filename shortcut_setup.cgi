#!/usr/bin/ruby
# -*- coding: utf-8 -*-

# Generate or rotate the append-only token used by post.cgi.
# Authenticate with the existing memo login name/password.
# The raw token is displayed once and is never stored server-side.
# Delete this CGI after setup if you do not need token rotation.

ENV['TZ'] = 'Asia/Tokyo'
$KCODE = 'u' if RUBY_VERSION < '1.9'
if defined?(Encoding)
  Encoding.default_external = Encoding::UTF_8
  Encoding.default_internal = Encoding::UTF_8
end
STDOUT.binmode if STDOUT.respond_to?(:binmode)

require File.join(File.dirname(__FILE__), 'oneline_http')
require 'digest/sha2'
require 'fileutils'
require 'openssl'

ROOT_DIR = File.dirname(__FILE__)
PRIVATE_DIR = File.expand_path('private', ROOT_DIR)
AUTH_FILE = File.join(PRIVATE_DIR, 'auth.conf')
TOKEN_FILE = File.join(PRIVATE_DIR, 'shortcut.conf')

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


def rfc3339_now
  now = Time.now
  zone = now.strftime('%z')
  if zone && zone.length == 5
    zone = zone[0, 3] + ':' + zone[3, 2]
  end
  now.strftime('%Y-%m-%dT%H:%M:%S') + zone.to_s
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


def valid_login?(username, password)
  config = parse_key_value_file(AUTH_FILE)
  return false if config.empty?
  return false if !secure_compare(username.to_s, config['username'].to_s)
  begin
    actual = password_digest(password, config['salt'], config['iterations'])
  rescue
    return false
  end
  secure_compare(actual, config['password_hash'].to_s)
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


def render(cgi, token, error_message)
  print_header(cgi)
  error_html = error_message.to_s.empty? ? '' : '<div class="auth-error">' + h(error_message) + '</div>'
  token_html = ''

  if !token.to_s.empty?
    token_html = '<div class="auth-message">Token created. Copy it now; the server stores only its SHA-256 digest.</div>' +
      '<div class="auth-row"><label for="shortcut_token">token</label>' +
      '<input id="shortcut_token" type="text" value="' + h(token) + '" readonly onclick="this.select()"></div>' +
      '<div class="auth-message">Delete shortcut_setup.cgi after copying the token. Running setup again rotates the token and invalidates the old one.</div>'
  end

  print <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>oneline Shortcut token setup</title>
<link rel="stylesheet" href="style.css?v=0.1.1">
</head>
<body>
<main class="auth-main">
  <section class="auth-box">
    #{token_html}
    #{error_html}
    <form method="post" action="" autocomplete="off">
      <div class="auth-row">
        <label for="username">name</label>
        <input id="username" type="text" name="username" autocomplete="username" autofocus>
      </div>
      <div class="auth-row">
        <label for="password">password</label>
        <input id="password" type="password" name="password" autocomplete="current-password">
      </div>
      <div class="auth-submit"><button type="submit">generate / rotate token</button></div>
    </form>
  </section>
</main>
</body>
</html>
HTML
end

cgi = OnelineCGI.new

if !File.exist?(AUTH_FILE)
  render(cgi, '', 'auth.conf not found. Configure normal login first.')
  exit
end

if ENV['REQUEST_METHOD'].to_s.upcase != 'POST'
  render(cgi, '', '')
  exit
end

username = param(cgi, 'username').to_s.strip
password = param(cgi, 'password')

if !valid_login?(username, password)
  sleep 1
  render(cgi, '', 'name or password is incorrect.')
  exit
end

begin
  token = random_bytes(32).unpack('H*')[0]
  digest = Digest::SHA256.hexdigest(token)
  created = rfc3339_now

  temp_file = TOKEN_FILE + '.tmp.' + Process.pid.to_s
  File.open(temp_file, 'w', 0600) do |file|
    file.write('algorithm=sha256' + "\n")
    file.write('token_hash=' + digest + "\n")
    file.write('created_at=' + created + "\n")
    file.flush
  end
  begin
    File.chmod(0600, temp_file)
  rescue
  end
  File.rename(temp_file, TOKEN_FILE)
  begin
    File.chmod(0600, TOKEN_FILE)
  rescue
  end

  render(cgi, token, '')
rescue Exception => e
  render(cgi, '', 'token creation failed: ' + e.class.to_s + ' ' + e.message.to_s)
end
