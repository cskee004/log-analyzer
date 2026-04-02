class ApiKey < ApplicationRecord
  has_secure_token :token

  validates :token,  presence: true, uniqueness: true
  validates :active, inclusion: { in: [true, false] }

  scope :active, -> { where(active: true) }

  def self.authenticate(raw_token)
    active.find_by(token: raw_token)
  end
end
