require 'pry'
require 'base64'
require 'openssl'
require 'json'
require 'securerandom'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/hash_with_indifferent_access'

module SecureToken

  class KeyPair < Struct.new(:encryption_key, :signing_key)

    def initialize(*args)
      super
      freeze
    end

  end

  class SecureTokenHash < HashWithIndifferentAccess

    class << self
      def from_token(token, key_pair)
        decryptor = SecureTokenService::Decryptor.new(SecureTokenService::JSONSerializer.new)
        decrypted_token = decryptor.decrypt_and_verify(token, key_pair)
        decrypted_token ? new.merge(decrypted_token) : nil
      end
    end

    def to_token(key_pair)
      encryptor = SecureTokenService::Encryptor.new(SecureTokenService::JSONSerializer.new)
      encryptor.encrypt_and_sign(self, key_pair)
    end

  end

  module SecureTokenService

    HASH_ALGO = 'sha256'
    SIGNATURE_LENGTH = OpenSSL::HMAC.digest(OpenSSL::Digest.new(HASH_ALGO), 'key', 'data').size

    CRYPT_ALGO = 'AES-128-CBC'

    class JSONSerializer

      def serialize(object)
        object.to_json
      end

      def deserialize(data)
        begin
          JSON.parse(data)
        rescue JSON::ParserError
          nil
        end
      end

    end

    class Encryptor

      def initialize(serializer)
        @salt = SecureRandom.random_bytes(8)
        @serializer = serializer
      end

      def encrypt_and_sign(data, key_pair)
        serialized = @serializer.serialize(data)
        encrypted = encrypt(serialized, key_pair.encryption_key)
        signed = sign(encrypted, key_pair.signing_key)
        Base64.urlsafe_encode64(signed)
      end

      private

      def sign(data, key)
        signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(HASH_ALGO), key, data)
        "#{signature.force_encoding('ascii-8bit')}#{data.force_encoding('ascii-8bit')}"
      end

      def encrypt(data, key)
        encrypter = OpenSSL::Cipher::Cipher.new CRYPT_ALGO
        encrypter.encrypt
        encrypter.pkcs5_keyivgen key, @salt

        encrypted = encrypter.update data
        encrypted << encrypter.final

        "#{@salt}#{encrypted}"
      end

    end

    class Decryptor

      def initialize(serializer)
        @serializer = serializer
      end

      def decrypt_and_verify(message, key_pair)
        begin
          message = Base64.urlsafe_decode64(message)
        rescue ArgumentError
          return nil
        end

        verified = verify(message, key_pair.signing_key)
        return nil unless verified


        begin
          decrypted = decrypt(verified, key_pair.encryption_key).force_encoding('utf-8')
        rescue OpenSSL::Cipher::CipherError
          return nil
        end

        @serializer.deserialize(decrypted)
      end

      private

      def verify(message, key)
        signature, payload = message[0, SIGNATURE_LENGTH], message[SIGNATURE_LENGTH..-1]
        valid_signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(HASH_ALGO), key, payload)
        signature == valid_signature ? payload : nil
      end

      def decrypt(data, key)
        salt, data = data[0, 8], data[8..-1]

        decrypter = OpenSSL::Cipher::Cipher.new CRYPT_ALGO
        decrypter.decrypt
        decrypter.pkcs5_keyivgen key, salt

        decrypted = decrypter.update data
        decrypted << decrypter.final

        decrypted
      end

    end

  end

end
