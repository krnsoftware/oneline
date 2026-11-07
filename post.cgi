#!/usr/bin/ruby
# -*- coding: utf-8 -*-

# Append-only endpoint for iOS/macOS Shortcuts.
# Target: Ruby 1.8.7 compatible syntax.
# Authentication: X-Oneline-Token header, SHA-256 digest stored server-side.

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
TOKEN_FILE = File.join(PRIVATE_DIR, 'shortcut.conf')
MAX_REQUEST_BYTES = 32768
MAX_MEMO_BYTES = 16384

FileUtils.mkdir_p(DATA_DIR)
FileUtils.mkdir_p(PRIVATE_DIR)


def one_line(text)
  text.to_s.gsub(/\r\n|\r|\n|\t/, ' ').strip
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


def valid_shortcut_token?(token)
  return false if token.to_s.empty?
  config = parse_key_value_file(TOKEN_FILE)
  expected = config['token_hash'].to_s
  return false if expected.empty?
  actual = Digest::SHA256.hexdigest(token.to_s)
  secure_compare(actual, expected)
end


def new_id
  seed = [Time.now.to_f, Process.pid, rand, ENV['REMOTE_ADDR'], random_hex(8)].join(':')
  Digest::SHA1.hexdigest(seed)[0, 16]
end


def month_path
  File.join(DATA_DIR, Time.now.strftime('%Y-%m') + '.txt')
end


def append_memo(body)
  timestamp = rfc3339_now
  id = new_id
  path = month_path
  line = [timestamp, id, body].join("\t") + "\n"

  File.open(path, 'a') do |file|
    file.flock(File::LOCK_EX)
    file.write(line)
    file.flush
  end
  begin
    File.chmod(0600, path)
  rescue
  end

  [id, timestamp]
end


def param(cgi, name)
  values = cgi.params[name]
  return '' if !values || values.empty?
  values[0].to_s
end


def response(status, text, extra_headers)
  print 'Status: ' + status + "\r\n"
  print "Content-Type: text/plain; charset=utf-8\r\n"
  print "Cache-Control: no-store\r\n"
  print "Referrer-Policy: no-referrer\r\n"
  print "X-Content-Type-Options: nosniff\r\n"
  extra_headers.each do |header|
    print header + "\r\n"
  end
  print "\r\n"
  print text
end

method = ENV['REQUEST_METHOD'].to_s.upcase
if method != 'POST'
  response('405 Method Not Allowed', "POST only\n", ['Allow: POST'])
  exit
end

content_length = ENV['CONTENT_LENGTH'].to_i
if content_length > MAX_REQUEST_BYTES
  response('413 Payload Too Large', "request too large\n", [])
  exit
end

if !File.exist?(TOKEN_FILE)
  response('503 Service Unavailable', "shortcut token is not configured\n", [])
  exit
end

if !valid_shortcut_token?(ENV['HTTP_X_ONELINE_TOKEN'])
  sleep 1
  response('403 Forbidden', "forbidden\n", [])
  exit
end

cgi = OnelineCGI.new
body = one_line(param(cgi, 'memo'))

if body.empty?
  response('400 Bad Request', "memo is empty\n", [])
  exit
end

if body.length > MAX_MEMO_BYTES
  response('413 Payload Too Large', "memo is too large\n", [])
  exit
end

begin
  id, timestamp = append_memo(body)
  response('201 Created', "OK\t" + id + "\t" + timestamp + "\n", [])
rescue Exception => e
  response('500 Internal Server Error', "save failed: " + e.class.to_s + "\n", [])
end
