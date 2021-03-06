# frozen_string_literal: true
module NETSNMP
  # Factory for the SNMP v3 Message format
  module Message
    extend self

    AUTHNONE           = OpenSSL::ASN1::OctetString.new(("\x00" * 12).b)
    PRIVNONE           = OpenSSL::ASN1::OctetString.new("")
    MSG_MAX_SIZE       = OpenSSL::ASN1::Integer.new(65507)
    MSG_SECURITY_MODEL = OpenSSL::ASN1::Integer.new(3)           # usmSecurityModel
    MSG_VERSION        = OpenSSL::ASN1::Integer.new(3)
    MSG_REPORTABLE     = 4

    # @param [String] payload of an snmp v3 message which can be decoded
    # @param [NETSMP::SecurityParameters, #decode] security_parameters knowns how to decode the stream
    #
    # @return [NETSNMP::ScopedPDU] the decoded PDU
    #
    def decode(stream, security_parameters: )
      engine_id, engine_boots, engine_time, _, auth_param, priv_param, pdu_payload = map_stream(stream)

      # error responses might come without AUTH
      if auth_param == AUTHNONE.value
        PDU.decode(pdu_payload)
      else
        ScopedPDU.decode(security_parameters.decode(pdu_payload,
                                                    salt: priv_param,
                                                    engine_boots: engine_boots,
                                                    engine_time: engine_time))
      end
    end

    def map_stream(stream)
      asn_tree = OpenSSL::ASN1.decode(stream)

      #version, headers, sec_params, pdu_payload
      _, _, sec_params, pdu_payload = asn_tree.value

      sec_params_asn = OpenSSL::ASN1.decode(sec_params.value).value
      sec_array = sec_params_asn.map(&:value)
      sec_array[1] = sec_array[1].to_i #engine_boots
      sec_array[2] = sec_array[2].to_i #engine_time
      sec_array << pdu_payload
      #[engine_id, engine_boots, engine_time, username, auth_param, priv_param, pdu_payload]
    end

    # @param [NETSNMP::ScopedPDU] the PDU to encode in the message
    # @param [NETSMP::SecurityParameters, #decode] security_parameters knowns how to decode the stream
    #
    # @return [String] the byte representation of an SNMP v3 Message
    #
    def encode(pdu, security_parameters: , engine_boots: 0, engine_time: 0)
      scoped_pdu, salt_param = security_parameters.encode(pdu, salt: PRIVNONE, 
                                                               engine_boots: engine_boots, 
                                                               engine_time: engine_time)

      sec_params = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::OctetString.new(security_parameters.engine_id),
        OpenSSL::ASN1::Integer.new(engine_boots),
        OpenSSL::ASN1::Integer.new(engine_time),
        OpenSSL::ASN1::OctetString.new(security_parameters.username),
        AUTHNONE,
        salt_param
      ])
      message_flags = MSG_REPORTABLE | security_parameters.security_level
      message_id    = OpenSSL::ASN1::Integer.new(SecureRandom.random_number(MAXREQUESTID))

      headers = OpenSSL::ASN1::Sequence.new([
        message_id, MSG_MAX_SIZE,
        OpenSSL::ASN1::OctetString.new( [String(message_flags)].pack("h*") ),
        MSG_SECURITY_MODEL
      ])

      encoded = pre_encode(headers, sec_params, scoped_pdu)

      if (signature = security_parameters.sign(encoded))
        #unless signature == (sig_2 = security_parameters.sign(encoded))
          #sig_3 = security_parameters.sign(encoded)
          #signature = case sig_3
            #when sig_2 then sig_2
            #when signature then signature
            #else security_parameters.sign(encoded)
          #end
        #end
        sec_params.value[4] = OpenSSL::ASN1::OctetString.new(signature)
        encoded = pre_encode(headers, sec_params, scoped_pdu)
      end

      encoded
    end

    private

    def pre_encode(headers, sec_params, scoped_pdu)
      OpenSSL::ASN1::Sequence([
        MSG_VERSION,
        headers,
        OpenSSL::ASN1::OctetString.new(sec_params.to_der),
        scoped_pdu
      ]).to_der.b
    end

  end
end
