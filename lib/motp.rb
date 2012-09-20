require 'digest/sha2'

DEFAULT_BIT_LENGTH     = 256
DEFAULT_DIGEST_LENGTH  = 6
DEFAULT_MAX_PERIOD     = 3 * 60

module Motp
  def self.otp(secret, pin, options = {})
    @options = { :time => Time::now }.merge(options)
    h = Digest::SHA2.new(bit_length) << "#{@options[:time].utc.tv_sec.to_s[0...-1]}#{secret}#{pin}"
    h.to_s[0...digest_length]
  end

  def self.check(secret, pin, otp, options = {})
    @options = { :time => Time::now, :max_period => (DEFAULT_MAX_PERIOD) }.merge(options)
    lower_limit = @options[:time] - @options[:max_period]
    upper_limit = @options[:time] + @options[:max_period]

    while lower_limit < upper_limit do
      return true if otp == self.otp(
          secret, pin,
          :time => lower_limit,
          :digest_length => otp.length,
          :bit_length => bit_length
      )
      lower_limit += 1
    end

    false
  end

  #

  private

  def self.digest_length
    @options[:digest_length] || DEFAULT_DIGEST_LENGTH
  end

  def self.bit_length 
    @options[:bit_length] || DEFAULT_BIT_LENGTH
  end
end
