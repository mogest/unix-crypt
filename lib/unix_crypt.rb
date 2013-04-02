require 'digest'
require 'securerandom'

module UnixCrypt
  def self.valid?(password, string)
    # Handle the original DES-based crypt(3)
    return password.crypt(string) == string if string.length == 13

    return false unless m = string.match(/\A\$([156])\$(?:rounds=(\d+)\$)?(.+)\$(.+)/)

    password = password.force_encoding('ASCII-8BIT') if password.respond_to?(:force_encoding)
    hash = IDENTIFIER_MAPPINGS[m[1]].hash(password, m[3], m[2] && m[2].to_i)
    hash == m[4]
  end

  class Base
    def self.build(password, salt = nil, rounds = nil)
      @salt = salt
      hashed = hash(password, salt, rounds)

      return "$#{identifier}$#{@salt}$#{hashed}"
    end

    protected
    def self.base64encode(input)
      b64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      input = input.bytes.to_a
      output = ""
      byte_indexes.each do |i3, i2, i1|
        b1, b2, b3 = i1 && input[i1] || 0, i2 && input[i2] || 0, i3 && input[i3] || 0
        output <<
          b64[  b1 & 0b00111111]         <<
          b64[((b1 & 0b11000000) >> 6) |
              ((b2 & 0b00001111) << 2)]  <<
          b64[((b2 & 0b11110000) >> 4) |
              ((b3 & 0b00000011) << 4)]  <<
          b64[ (b3 & 0b11111100) >> 2]
      end

      remainder = 3 - (length % 3)
      remainder = 0 if remainder == 3
      output[0..-1-remainder]
    end
  end

  class MD5 < Base
    def self.digest; Digest::MD5; end
    def self.length; 16; end
    def self.identifier; 1; end

    def self.byte_indexes
      [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5], [nil, nil, 11]]
    end

    def self.hash(password, salt = nil, ignored = nil)
      salt = SecureRandom.hex(4) if salt.nil?
      @salt = salt[0..7]

      b = digest.digest("#{password}#{@salt}#{password}")
      a_string = "#{password}$1$#{@salt}#{b * (password.length/length)}#{b[0...password.length % length]}"

      password_length = password.length
      while password_length > 0
        a_string += (password_length & 1 != 0) ? "\x0" : password[0].chr
        password_length >>= 1
      end

      input = digest.digest(a_string)

      1000.times do |index|
        c_string = ((index & 1 != 0) ? password : input)
        c_string += @salt unless index % 3 == 0
        c_string += password unless index % 7 == 0
        c_string += ((index & 1 != 0) ? input : password)
        input = digest.digest(c_string)
      end

      base64encode(input)
    end
  end

  class SHABase < Base
    def self.hash(password, salt = nil, rounds = nil)
      rounds ||= 5000
      rounds = 1000        if rounds < 1000
      rounds = 999_999_999 if rounds > 999_999_999

      salt = SecureRandom.hex(8) if salt.nil?
      @salt = salt[0..15]

      b = digest.digest("#{password}#{@salt}#{password}")

      a_string = password + @salt + b * (password.length/length) + b[0...password.length % length]

      password_length = password.length
      while password_length > 0
        a_string += (password_length & 1 != 0) ? b : password
        password_length >>= 1
      end

      input = a = digest.digest(a_string)

      dp = digest.digest(password * password.length)
      p = dp * (password.length/length) + dp[0...password.length % length]

      ds = digest.digest(@salt * (16 + a.bytes.first))
      s = ds * (@salt.length/length) + ds[0...@salt.length % length]

      rounds.times do |index|
        c_string = ((index & 1 != 0) ? p : input)
        c_string += s unless index % 3 == 0
        c_string += p unless index % 7 == 0
        c_string += ((index & 1 != 0) ? input : p)
        input = digest.digest(c_string)
      end

      base64encode(input)
    end
  end

  class SHA256 < SHABase
    def self.digest; Digest::SHA256; end
    def self.length; 32; end
    def self.identifier; 5; end

    def self.byte_indexes
      [[0, 10, 20], [21, 1, 11], [12, 22, 2], [3, 13, 23], [24, 4, 14], [15, 25, 5], [6, 16, 26], [27, 7, 17], [18, 28, 8], [9, 19, 29], [nil, 31, 30]]
    end
  end

  class SHA512 < SHABase
    def self.digest; Digest::SHA512; end
    def self.length; 64; end
    def self.identifier; 6; end
    def self.byte_indexes
      [[0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4], [47, 5, 26], [6, 27, 48], [28, 49, 7], [50, 8, 29], [9, 30, 51], [31, 52, 10],
        [53, 11, 32], [12, 33, 54], [34, 55, 13], [56, 14, 35], [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19], [62, 20, 41], [nil, nil, 63]]
    end
  end

  IDENTIFIER_MAPPINGS = {'1' => MD5, '5' => SHA256, '6' => SHA512}
end
