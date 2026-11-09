# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

# Calls the internal redaction service. Never logs the request or response body.
# Fail closed: any error, timeout, or non-200 raises and the caller must not persist.
class PiiRedactor
  class Unavailable < StandardError; end

  TIMEOUT_SECONDS = 0.3

  def self.redact(text)
    new.redact(text)
  end

  def redact(text)
    response = post(text)
    raise Unavailable, 'redaction service rejected the request' unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    text_out = parsed['text']
    entities = parsed['entities']
    version = parsed['engine_version']
    raise Unavailable, 'redaction service returned an unexpected body' unless text_out.is_a?(String) && entities.is_a?(Hash)

    Result.new(text_out, stringify_counts(entities), version.to_s)
  rescue Timeout::Error, SocketError, SystemCallError, JSON::ParserError, IOError
    raise Unavailable, 'redaction service unavailable'
  end

  private

  def post(text)
    uri = URI(ENV.fetch('PII_REDACTION_URL'))
    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request['Accept'] = 'application/json'
    request.body = JSON.generate({ text: text })
    Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', open_timeout: TIMEOUT_SECONDS, read_timeout: TIMEOUT_SECONDS) do |http|
      http.request(request)
    end
  rescue KeyError
    raise Unavailable, 'redaction service unavailable'
  end

  def stringify_counts(entities)
    entities.each_with_object({}) do |(key, value), out|
      out[key.to_s] = Integer(value)
    end
  rescue ArgumentError, TypeError
    raise Unavailable, 'redaction service returned an unexpected body'
  end

  Result = Struct.new(:text, :entities, :engine_version)
end
