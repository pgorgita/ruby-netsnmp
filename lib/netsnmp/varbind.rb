# frozen_string_literal: true
module NETSNMP
  # Abstracts the PDU variable structure into a ruby object
  #

  class Varbind

    #Symbol needed for pdu errors: PDU#add_varbinds
    #
    # Array order is important as the index is the ASN tag for every data type
    DATA_TYPES = [:ipaddress, :counter32, :gauge, :timetick, :opaque, :nsap,
                  :counter64, :uinteger, :string, :integer, :boolean, :symbol,
                  :nil, :oid]

    CLASS_TO_TYPE = { "String"=> 8, "Fixnum"=> 9, "Bignum"=> 9, "Integer"=> 9,
                      "IPAddr"=> 0, "TrueClass"=> 10, "FalseClass"=> 10,
                      "Symbol"=> 11, "NilClass"=>  12, "NETSNMP::Timetick"=> 3,
                      "OpenSSL::BN" => 9 }

    attr_reader :oid, :value

    def initialize(oid , value: nil, type: nil, **opts)
      @oid = OID.build(oid)
      type_tag_and_value(type, value)
    end

    def to_s
      "#<#{self.class}:0x#{object_id.to_s(16)} @oid=#{@oid} @value=#{@value}>"
    end

    def to_der
      to_asn.to_der
    end

    def to_asn
      asn_oid = OID.to_asn(@oid)
      asn_val = case @type
        when :timetick then @value.to_asn
        when :string, :symbol then OpenSSL::ASN1::OctetString.new(@value)
        when :integer then OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(@value))
        when :boolean then OpenSSL::ASN1::Boolean.new(@value)
        when :nil then OpenSSL::ASN1::Null.new(nil)
        when :oid then OID.to_asn(@value)
        when :ipaddress then OpenSSL::ASN1::ASN1Data.new(@value.hton, @asn_tag, :APPLICATION)
        else
          OpenSSL::ASN1::ASN1Data.new(@value, @asn_tag, :APPLICATION)
      end
      OpenSSL::ASN1::Sequence.new( [asn_oid, asn_val] )
    end

    private

    def type_tag_and_value(type, value)
      value_class = value.class.name
      @type, @asn_tag = case type
        when nil
          case value_class
            when /^OpenSSL::ASN1/
              @asn = value
              value, typ = value_per_asn1
              [typ, @asn.tag]
            when *CLASS_TO_TYPE.keys
              typ = type_from_class(value_class)
              [typ, tag_from_type(typ)]
            else
              raise Error, "unsupported varbind value:#{value.inspect}"
          end
        when *DATA_TYPES
          [type, tag_from_type(type)]
        else
          raise Error, "unsupported varbind type:#{type.inspect}"
      end

      @value = if @type == :ipaddress && value_class != "IPAddr"
        IPAddr.new(value.to_s)
      elsif @type == :timetick && value_class != "NETSNMP::Timetick"
        Timetick.new(value.to_i)
      else
        value
      end

    end

    def asn_types
      DATA_TYPES[0..7]
    end

    def type_from_tag(tag)
      asn_types[tag] ||
      raise(Error, "unsupported varbind tag:#{tag.inspect}")
    end

    def tag_from_type(type)
      asn_types.find_index(type)
    end

    def type_from_class(value_class)
      DATA_TYPES[ CLASS_TO_TYPE[value_class] ]
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
         [ asn_value, :oid ]
        else
          Kernel.puts @asn.inspect unless @asn.is_a?(OpenSSL::ASN1::ASN1Data)
          # OpenSSL::ASN1::ASN1Data and any other
          # ASN1 will be decoded per tag & tagclass
          # already returns [value , type_symbol]
          value_per_tag_class(asn_value)
      end
      [oid_error_check(value), type]
    end

    def value_per_tag_class(asn_value)
      asn_tag = @asn.tag
      case tag_class = @asn.tag_class
        when :CONTEXT_SPECIFIC
          case asn_tag
            when 0
              :no_such_instance_0
            when 1
              :no_such_instance_1
            when 2
              :end_of_mib
            else
              "context_specific_#{asn_tag}".to_sym
          end
        when :UNIVERSAL, :APPLICATION
          Array(case asn_tag
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
            when 5, 7 # NSAP(5), SN UInteger(7)
              asn_value
            else
              raise(Error, "unknown asn tag:#{@asn.inspect}}")
          end) << type_from_tag(asn_tag)
        else
          raise(Error, "unknown asn tag_class:#{@asn.inspect}}")
      end
    end

    def hex_string_decode(hex)
      hex.dump.include?("\\x") ? hex.unpack("H*")[0] : hex
    end

    def oid_error_check(value)
      case @oid
        when "1.3.6.1.6.3.15.1.1.1.0" then "Unsupported Security Levels"
        when "1.3.6.1.6.3.15.1.1.2.0" then "Not In Time Windows"
        when "1.3.6.1.6.3.15.1.1.3.0" then "Unknown User Names"
        when "1.3.6.1.6.3.15.1.1.4.0" then "Unknown EngineIDs"
        when "1.3.6.1.6.3.15.1.1.5.0" then "Wrong Digests"
        when "1.3.6.1.6.3.15.1.1.6.0" then "Decryption Errors"
        else
          return value
      end + "(##{value})"
    end

  end
end
