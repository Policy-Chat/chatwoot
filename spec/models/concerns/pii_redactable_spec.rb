# frozen_string_literal: true

require 'rails_helper'

RSpec.describe PiiRedactable do
  let(:ssn) { '900-12-3456' }
  let(:redacted) { 'ssn [SSN]' }

  before do
    allow(PiiRedactor).to receive(:redact).and_return(
      PiiRedactor::Result.new(redacted, { 'SSN' => 1 }, 'presidio-2.2.360')
    )
  end

  it 'persists the token, the count, and a webhook body that is already redacted' do
    message = create(:message, content: "ssn #{ssn}", private: true)

    expect(message.reload.content).to eq(redacted)
    expect(message.content).not_to include(ssn)
    expect(message.processed_message_content).not_to include(ssn)
    expect(message.additional_attributes['redaction']).to eq(
      'entities' => { 'SSN' => 1 },
      'engine_version' => 'presidio-2.2.360'
    )
    expect(message.webhook_data[:content]).to eq(redacted)
    expect(message.webhook_data[:content]).not_to include(ssn)
  end

  it 'redacts an activity message the same way' do
    message = create(:message, message_type: :activity, content: "note #{ssn}")

    expect(message.reload.content).to eq(redacted)
    expect(PiiRedactor).to have_received(:redact).with("note #{ssn}")
  end

  it 'does not persist when the redaction service is down' do
    allow(PiiRedactor).to receive(:redact).and_raise(PiiRedactor::Unavailable)
    expect do
      create(:message, content: "ssn #{ssn}")
    end.to raise_error(PiiRedactor::Unavailable)
    expect(Message.where('content LIKE ?', "%#{ssn}%")).to be_empty
  end

  it 'redacts again when the content changes' do
    message = create(:message, content: 'hello')
    allow(PiiRedactor).to receive(:redact).and_return(
      PiiRedactor::Result.new('updated [SSN]', { 'SSN' => 1 }, 'presidio-2.2.360')
    )

    message.update!(content: "changed #{ssn}")

    expect(message.reload.content).to eq('updated [SSN]')
    expect(message.content).not_to include(ssn)
  end
end
