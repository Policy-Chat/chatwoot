# frozen_string_literal: true

require 'spec_helper'
require 'json'
require_relative '../../lib/pii_redactor'

# COR-419. Same 500-row file the redaction service pytest scores.
# Counts and row ids only. Request text is not printed.
RSpec.describe 'PII corpus' do
  corpus_path = File.expand_path('../pii_corpus.jsonl', __dir__)
  gaps_path = File.expand_path('../pii_known_gaps.json', __dir__)

  def self.load_jsonl(path)
    File.readlines(path, chomp: true).reject(&:empty?).map { |line| JSON.parse(line) }
  end

  let(:rows) { self.class.load_jsonl(corpus_path) }
  let(:gaps) { JSON.parse(File.read(gaps_path)) }

  around do |example|
    if ENV['PII_REDACTION_URL'].to_s.empty?
      raise PiiRedactor::Unavailable, 'PII_REDACTION_URL is required for the corpus gate'
    end

    host = URI(ENV.fetch('PII_REDACTION_URL')).host
    WebMock.disable_net_connect!(allow_localhost: true, allow: host)
    example.run
  ensure
    WebMock.disable_net_connect!(allow_localhost: true)
  end

  it 'is 500 synthetic rows and records the known split-message gap' do
    expect(rows.length).to eq(500)
    expect(rows.map { |row| row.fetch('id') }.uniq.length).to eq(500)
    expect(gaps.fetch('known_gaps').any? { |item| item.include?('split across two messages') }).to be(true)
  end

  it 'keeps SSN recall at or above 99 percent and false positives at or below 2 percent' do
    scored = score_rows(rows)
    ssn_rows = rows.select { |row| row.fetch('expected_entities')['SSN'] }
    negatives = rows.select { |row| row.fetch('expected_entities') == {} }

    expect(ssn_rows).not_to be_empty
    expect(negatives).not_to be_empty

    hits = ssn_rows.count { |row| scored.fetch(row.fetch('id')) }
    recall = hits.to_f / ssn_rows.length
    expect(recall).to((be >= 0.99), "SSN recall #{format('%.3f', recall)} on #{ssn_rows.length} rows")

    false_positives = negatives.count { |row| !scored.fetch(row.fetch('id')) }
    rate = false_positives.to_f / negatives.length
    expect(rate).to((be <= 0.02), "false positive rate #{format('%.3f', rate)} on #{negatives.length} rows")
  end

  it 'matches every row' do
    scored = score_rows(rows)
    missed = rows.reject { |row| scored.fetch(row.fetch('id')) }.map { |row| row.fetch('id') }
    expect(missed).to eq([])
  end

  def score_rows(rows)
    rows.each_with_object({}) do |row, out|
      result = PiiRedactor.redact(row.fetch('text'))
      out[row.fetch('id')] = result.text == row.fetch('expected_redacted_text') &&
                              result.entities == row.fetch('expected_entities')
    end
  end
end
