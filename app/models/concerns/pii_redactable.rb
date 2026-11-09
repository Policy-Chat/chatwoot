# frozen_string_literal: true

module PiiRedactable
  extend ActiveSupport::Concern

  included do
    # before_save copies content into processed_message_content before before_create
    # runs, so the redaction also rewrites processed_message_content.
    before_create :redact_pii
    before_update :redact_pii, if: :content_changed?
  end

  private

  def redact_pii
    return if content.blank?

    result = PiiRedactor.redact(content)
    self.content = result.text
    self.processed_message_content = content.to_s.truncate(150_000)
    current = additional_attributes.is_a?(Hash) ? additional_attributes.deep_stringify_keys : {}
    current['redaction'] = {
      'entities' => result.entities,
      'engine_version' => result.engine_version
    }
    self.additional_attributes = current
  end
end

# Rejects conversation custom-attribute keys that are not operational, an intake
# field, or a defined conversation attribute. Existing stored keys are left alone.
module ConversationCustomAttributeGuard
  extend ActiveSupport::Concern

  OPERATIONAL_KEYS = %w[
    correlation_id
    tracking_missing
    intake_state
    intake_messages
    intake_handed_off
    last_bot_msg_id
    product
    sage_session_id
    sage_last_msg_id
    sage_profile
  ].freeze
  INTAKE_KEY = /\Aintake_[a-z0-9_]+\z/

  included do
    validate :custom_attribute_keys_are_allowed
  end

  private

  def custom_attribute_keys_are_allowed
    return unless custom_attributes.is_a?(Hash)
    return unless will_save_change_to_custom_attributes?

    previous = custom_attributes_in_database
    previous_keys = previous.is_a?(Hash) ? previous.keys.map(&:to_s) : []
    incoming = custom_attributes.keys.map(&:to_s) - previous_keys
    rejected = incoming.reject { |key| allowed_custom_attribute_key?(key) }
    return if rejected.empty?

    errors.add(:custom_attributes, "rejected keys: #{rejected.sort.join(', ')}")
  end

  def allowed_custom_attribute_key?(key)
    OPERATIONAL_KEYS.include?(key) || key.match?(INTAKE_KEY) || defined_conversation_attribute_keys.include?(key)
  end

  def defined_conversation_attribute_keys
    return [] unless account

    account.custom_attribute_definitions.conversation_attribute.pluck(:attribute_key)
  end
end
