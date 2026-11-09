# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PiiRedactor do
  let(:ssn) { '900-12-3456' }

  around do |example|
    original = ENV.fetch('PII_REDACTION_URL', nil)
    example.run
  ensure
    original.nil? ? ENV.delete('PII_REDACTION_URL') : ENV['PII_REDACTION_URL'] = original
  end

  it 'returns the redacted text and counts and does not log the body' do
    ENV['PII_REDACTION_URL'] = 'http://redaction.test/redact'
    stub_request(:post, 'http://redaction.test/redact')
      .with(body: { text: "ssn #{ssn}" }.to_json)
      .to_return(status: 200, body: { text: 'ssn [SSN]', entities: { 'SSN' => 1 }, engine_version: 'presidio-2.2.360' }.to_json)

    log = StringIO.new
    allow(Rails).to receive(:logger).and_return(Logger.new(log))
    result = described_class.redact("ssn #{ssn}")

    expect(result.text).to eq('ssn [SSN]')
    expect(result.entities).to eq('SSN' => 1)
    expect(result.engine_version).to eq('presidio-2.2.360')
    expect(log.string).not_to include(ssn)
  end

  it 'raises and does not return text when the service is down' do
    ENV['PII_REDACTION_URL'] = 'http://redaction.test/redact'
    stub_request(:post, 'http://redaction.test/redact').to_timeout

    expect { described_class.redact("ssn #{ssn}") }.to raise_error(described_class::Unavailable)
  end

  it 'raises when the service URL is unset' do
    ENV.delete('PII_REDACTION_URL')
    expect { described_class.redact('hello') }.to raise_error(described_class::Unavailable)
  end
end
