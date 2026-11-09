# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ConversationCustomAttributeGuard do
  it 'keeps an operational key and an intake field' do
    conversation = create(:conversation)
    conversation.custom_attributes = { 'correlation_id' => 'abc', 'intake_zip' => '10001' }
    expect(conversation).to be_valid
  end

  it 'rejects a free-text key' do
    conversation = create(:conversation)
    conversation.custom_attributes = { 'note' => 'call me about 900-12-3456' }
    expect(conversation).not_to be_valid
    expect(conversation.errors[:custom_attributes].join).to include('note')
  end
end
