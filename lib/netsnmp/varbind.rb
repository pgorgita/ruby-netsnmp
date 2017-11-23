# frozen_string_literal: true
module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #

  class Varbind

    #Symbol needed for pdu errors: PDU#add_varbinds
    #
    # Array order is important as the index is the ASN tag
    TYPES = [:ipaddress, :counter32, :gauge, :timetick, :opaque, :nsap,
                  :counter64, :uinteger, :string, :integer, :boolean, :symbol,
                  :nil, :oid]

    CLASS_TO_TYPE = { "String"=> 8, "Fixnum"=> 9, "Bignum"=> 9, "Integer"=> 9,
                      "IPAddr"=> 0, "TrueClass"=> 10, "FalseClass"=> 10,
                      "Symbol"=> 11, "NilClass"=>  12, "NETSNMP::Timetick"=> 3,
                      "OpenSSL::BN" => 9 }

    # check #hex_string_decode
    PRINTABLE = (32..126).to_a
    $HEXSTRING_HEX_OIDS = []
    $HEXSTRING_STR_OIDS = []

    attr_reader :oid, :value, :asn

    def initialize(oid , value: nil, type: nil, **opts)
      @oid_asn = case oid
       when OpenSSL::ASN1::ObjectId then oid
       else
         oid = oid[1..-1] if oid.start_with?('.')
         OpenSSL::ASN1::ObjectId.new(oid)
      end
      @oid = @oid_asn.oid
      type_tag_and_value(type, value)
      rescue OpenSSL::ASN1::ASN1Error => e
        raise Error, e.message
    end

    def to_s
      "#<#{self.class}:0x#{object_id.to_s(16)} @oid=#{@oid} @value=#{@value}>"
    end

    def to_der
      to_asn.to_der
    end

    def to_asn
      OpenSSL::ASN1::Sequence.new( [@oid_asn, @asn] )
    end

    private

    def type_tag_and_value(type, value)
      value_class = value.class.name
      @type, @asn_tag, @value = case type
        when nil
          case value_class
            when /^OpenSSL::ASN1/
              @asn = value
              value, typ = value_per_asn1
              [typ, @asn.tag, value]
            when *CLASS_TO_TYPE.keys
              typ = type_from_class(value_class)
              [typ, tag_from_type(typ), value]
            else
              raise Error, "unsupported varbind value:#{value.inspect}"
          end
        when *TYPES
          value = case type
            when :ipaddress then IPAddr.new(value.to_s)
            when :timetick then Timetick.new(value.to_i)
            else value
          end
          [type, tag_from_type(type), value]
        else
          raise Error, "unsupported varbind type:#{type.inspect}"
      end
      build_asn
    end

    def build_asn
      @asn ||= case @type
        when :timetick then @value.to_asn
        when :string, :symbol then OpenSSL::ASN1::OctetString.new(@value)
        when :integer then OpenSSL::ASN1::Integer.new(@value.to_bn)
        when :boolean then OpenSSL::ASN1::Boolean.new(@value)
        when :nil then OpenSSL::ASN1::Null.new(nil)
        when :oid then OpenSSL::ASN1::ObjectId.new(@value)
        when :ipaddress then OpenSSL::ASN1::ASN1Data.new(@value.hton, @asn_tag, :APPLICATION)
        else
          OpenSSL::ASN1::ASN1Data.new(@value, @asn_tag, :APPLICATION)
      end
    end

    def asn_types
      TYPES[0..7]
    end

    def type_from_tag(tag)
      asn_types[tag] ||
      raise(Error, "unsupported varbind tag:#{tag.inspect}")
    end

    def tag_from_type(type)
      asn_types.find_index(type)
    end

    def type_from_class(klass)
      TYPES[ CLASS_TO_TYPE[klass] ]
    end

    def value_per_asn1
      asn_value = @asn.value
      value, type = case @asn
        when OpenSSL::BN, OpenSSL::ASN1::Integer
          [ asn_value.to_i, :integer ]
        when OpenSSL::ASN1::OctetString
          [ hex_string_decode(asn_value), :string ]
        when OpenSSL::ASN1::Boolean
          [ asn_value, :boolean ]
        when OpenSSL::ASN1::Null
          [ asn_value, :nil ]
        when OpenSSL::ASN1::ObjectId
          [ @asn.oid, :oid ]
        else
          Kernel.puts @asn.inspect unless @asn.is_a?(OpenSSL::ASN1::ASN1Data)
          # OpenSSL::ASN1::ASN1Data and any other
          # ASN1 will be decoded per tag & tagclass
          # already returns [value , type_symbol]
          value_per_tag_class(asn_value)
      end
      oid_error_check(value, type)
    end

    def value_per_tag_class(asn_value)
      asn_tag = @asn.tag
      case tag_class = @asn.tag_class
        when :UNIVERSAL, :APPLICATION
          Array(
            case asn_tag
              when 0 # IP Address
                IPAddr.new_ntoh(asn_value)
              when 1, 2 # ASN counter 32(1), Gauge(2)
                asn_value.unpack("B*")[0].to_i(2)
              when 3 # timeticks
                Timetick.new(asn_value.unpack("B*")[0].to_i(2) || 0)
              when 4 # opaque
                hex_string_decode(asn_value)
              when 6 # ASN Counter 64
                asn_value.unpack("H*")[0].to_i(16)
              else# NSAP(5), SN UInteger(7)...any other
                asn_value
              end
          ) << type_from_tag(asn_tag)
        else
          case [tag_class, asn_tag]
            when [:CONTEXT_SPECIFIC, 0] then :no_such_instance_0
            when [:CONTEXT_SPECIFIC, 1] then :no_such_instance_1
            when [:CONTEXT_SPECIFIC, 2] then :end_of_mib
            else
              val = asn_value.to_s.split(/\W+/).join("_")
              "#{tag_class.to_s.downcase}_#{asn_tag}_#{val}".to_sym
          end
      end
    end

    #
    # Opaque: https://tools.ietf.org/html/rfc2578#section-7.1.9

    # '(...)Opaque type supports the capability to pass arbitrary ASN.1
    #  syntax (...) encoded as an OCTET STRING, in effect "double-wrapping"
    #  the original ASN.1 value(...)'
    #
    # given this, in order to unwrap correctly the value it is needed to know
    # if the value is already ASCII or if it needs hex unpacking from the oid
    # specification on the MIB.
    #
    # Provide oids to $HEXSTRING_HEX_OIDS and to $HEXSTRING_STR_OIDS force the decison
    # Use regex if needed for indexes:
    # $HEXSTRING_HEX_OIDS << /^1.3.6.1.4.1.2011.5.117.1.2.1.1.\d+$/
    # $HEXSTRING_STR_OIDS << /^1.3.6.1.2.1.47.1.1.1.1.8.\d+$/
    #
    # If oid is not found on these global vars the value will be "guessed".
    # It has a very high success rate, but there are always exceptions
    # For precision please add always your known oids into the global
    #
    def hex_string_decode(value)
      return value if value == ""
      case @oid
        when *$HEXSTRING_HEX_OIDS then unpack_hex(value)
        when *$HEXSTRING_STR_OIDS then printable(value)
        else #lets attempt an educated guess
          if !unprintable_bytes(value).empty? || empty_print(value)
            unpack_hex(value)
          else
            printable(value)
          end
      end
    end

    def unpack_hex(value)
      @unpack_hex ||= value.unpack("H*")[0]
    end

    def value_bytes(value)
      @value_bytes ||= value.bytes
    end

    def printable_bytes(value)
      @printable_bytes ||= value_bytes(value).select{|b| PRINTABLE.include?(b) }
    end

    def unprintable_bytes(value)
      @unprintable_bytes ||= value_bytes(value).reject{|b| PRINTABLE.include?(b) }
    end

    def printable(value)
      @printable ||= printable_bytes(value).pack('c*').strip
    end

    def empty_print(value)
      printable_bytes(value).reject{|b| [0, 32].include?(b) }.empty?
    end

    #usmStats error counter oids
    def oid_error_check(value, type)
      error = case @oid
        when "1.3.6.1.6.3.15.1.1.1.0" then "unsupported_security_levels"
        when "1.3.6.1.6.3.15.1.1.2.0" then "not_in_time_windows"
        when "1.3.6.1.6.3.15.1.1.3.0" then "unknown_user_names"
        when "1.3.6.1.6.3.15.1.1.4.0" then "unknown_engineid"
        when "1.3.6.1.6.3.15.1.1.5.0" then "wrong_digests"
        when "1.3.6.1.6.3.15.1.1.6.0" then "decryption_errors"
        else return [ value, type ]
      end
      ["#{error}_#{value}".to_sym, :symbol]
    end

  end
end
