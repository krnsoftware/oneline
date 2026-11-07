# -*- coding: utf-8 -*-

# Minimal CGI helpers for oneline.
# Intentionally avoids Ruby's cgi library so the application can run on
# Ruby versions where the full CGI implementation is not bundled.
# Compatible with Ruby 1.8.7 syntax.

module OnelineHTTP
  def self.binary_string(text)
    value = text.to_s.dup
    if defined?(Encoding)
      value.force_encoding(Encoding::ASCII_8BIT)
    end
    value
  end

  def self.utf8_string(text)
    value = text.to_s
    if defined?(Encoding)
      value.force_encoding(Encoding::UTF_8)
    end
    value
  end

  def self.hex_byte?(text)
    !!(text.to_s =~ /\A[0-9A-Fa-f]{2}\z/)
  end

  def self.url_decode(text)
    source = binary_string(text)
    out = binary_string('')
    i = 0

    while i < source.length
      char = source[i, 1]
      if char == '+'
        out << ' '
        i += 1
      elsif char == '%' && i + 2 < source.length
        hex = source[i + 1, 2]
        if hex_byte?(hex)
          out << [hex.to_i(16)].pack('C')
          i += 3
        else
          out << char
          i += 1
        end
      else
        out << char
        i += 1
      end
    end

    utf8_string(out)
  end

  def self.url_encode(text)
    bytes = binary_string(text).unpack('C*')
    out = ''
    bytes.each do |byte|
      if (byte >= 0x30 && byte <= 0x39) ||
         (byte >= 0x41 && byte <= 0x5a) ||
         (byte >= 0x61 && byte <= 0x7a) ||
         byte == 0x2d || byte == 0x2e || byte == 0x5f || byte == 0x7e
        out << byte.chr
      elsif byte == 0x20
        out << '+'
      else
        out << sprintf('%%%02X', byte)
      end
    end
    out
  end

  def self.html_escape(text)
    text.to_s.gsub('&', '&amp;').
      gsub('<', '&lt;').
      gsub('>', '&gt;').
      gsub('"', '&quot;').
      gsub("'", '&#39;')
  end

  def self.add_param(params, key, value)
    params[key] = [] if !params.has_key?(key)
    params[key] << value
  end

  def self.parse_urlencoded(text)
    params = {}
    return params if text.to_s.empty?

    text.to_s.split(/[&;]/, -1).each do |pair|
      key, value = pair.split('=', 2)
      key = url_decode(key.to_s)
      value = url_decode(value.to_s)
      add_param(params, key, value)
    end
    params
  end

  def self.multipart_boundary(content_type)
    text = content_type.to_s
    if text =~ /boundary="([^"]+)"/i
      return $1
    end
    if text =~ /boundary=([^;\s]+)/i
      return $1
    end
    ''
  end

  def self.parse_multipart(body, content_type)
    params = {}
    boundary = multipart_boundary(content_type)
    return params if boundary.empty?

    delimiter = '--' + boundary
    binary_string(body).split(delimiter).each do |part|
      next if part.nil? || part.empty?
      part = part.sub(/\A\r?\n/, '')
      next if part == '--' || part =~ /\A--\r?\n?\z/
      part = part.sub(/\r?\n\z/, '')
      part = part.sub(/--\z/, '')

      headers, value = part.split(/\r?\n\r?\n/, 2)
      next if !headers || value.nil?

      disposition = nil
      headers.each_line do |line|
        if line =~ /\AContent-Disposition\s*:/i
          disposition = line.strip
          break
        end
      end
      next if disposition.nil?
      next if disposition =~ /;\s*filename\s*=/i

      name = nil
      if disposition =~ /;\s*name="([^"]*)"/i
        name = $1
      elsif disposition =~ /;\s*name=([^;\s]+)/i
        name = $1
      end
      next if name.nil? || name.empty?

      value = value.sub(/\r?\n\z/, '')
      add_param(params, utf8_string(name), utf8_string(value))
    end
    params
  end

  def self.merge_params(target, source)
    source.each do |key, values|
      target[key] = [] if !target.has_key?(key)
      values.each { |value| target[key] << value }
    end
    target
  end

  def self.read_request_params
    params = parse_urlencoded(ENV['QUERY_STRING'].to_s)
    method = ENV['REQUEST_METHOD'].to_s.upcase
    return params if method != 'POST' && method != 'PUT' && method != 'PATCH'

    length = ENV['CONTENT_LENGTH'].to_i
    return params if length <= 0

    body = STDIN.read(length)
    content_type = ENV['CONTENT_TYPE'].to_s
    body_params = if content_type =~ /multipart\/form-data/i
      parse_multipart(body, content_type)
    else
      parse_urlencoded(body)
    end
    merge_params(params, body_params)
  end

  def self.header(options)
    options = {} if options.nil?
    lines = []

    status = options['status']
    location = options['location']
    type = options['type'].to_s
    type = 'text/html' if type.empty?
    charset = options['charset'].to_s

    lines << 'Status: ' + status.to_s if status && !status.to_s.empty?
    lines << 'Location: ' + location.to_s if location && !location.to_s.empty?

    content_type = type
    content_type += '; charset=' + charset if !charset.empty?
    lines << 'Content-Type: ' + content_type

    skip = { 'status' => true, 'location' => true, 'type' => true, 'charset' => true }
    options.each do |key, value|
      key = key.to_s
      next if skip[key]
      next if value.nil?
      lines << key + ': ' + value.to_s
    end

    lines.join("\r\n") + "\r\n\r\n"
  end
end

class OnelineCGI
  attr_reader :params

  def initialize
    @params = OnelineHTTP.read_request_params
  end

  def header(options)
    OnelineHTTP.header(options)
  end
end
