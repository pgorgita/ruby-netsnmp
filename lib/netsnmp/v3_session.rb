# frozen_string_literal: true
module NETSNMP
  # Abstraction for the v3 semantics.
  class V3Session < Session

    # @param [String, Integer] version SNMP version (always 3)
    def initialize(version: 3, context: "", **opts)
      @context = context
      @security_parameters = opts.delete(:security_parameters) 
      super
    end

    # @see {NETSNMP::Session#build_pdu}
    #
    # @return [NETSNMP::ScopedPDU] a pdu
    def build_pdu(type, *vars)
      probe_for_engine unless defined?(@engine_time_gap)
      ScopedPDU.build(type, headers: [@security_parameters.engine_id, @context], varbinds: vars)
    end

    private

    def validate(**options)
      super
      if s = @security_parameters
        # inspect public API
        unless s.respond_to?(:encode) &&
               s.respond_to?(:decode) &&
               s.respond_to?(:sign)
          raise Error, "#{s} doesn't respect the sec params public API (#encode, #decode, #sign)" 
        end 
      else
        @security_parameters = SecurityParameters.new(security_level: options[:security_level], 
                                                      username:       options[:username],
                                                      auth_protocol:  options[:auth_protocol],
                                                      priv_protocol:  options[:priv_protocol],
                                                      auth_password:  options[:auth_password],
                                                      priv_password:  options[:priv_password])

      end
    end

    # sends a probe snmp v3 request, to get the additional info with which to handle the security aspect
    #
    def probe_for_engine
      report_sec_params = SecurityParameters.new(security_level: 0,
                                                 username: @security_parameters.username)
      pdu = ScopedPDU.build(:get, headers: [])
      encoded_report_pdu = Message.encode(pdu, security_parameters: report_sec_params)

      encoded_response_pdu = @transport.send(encoded_report_pdu)

      engine_id, @engine_boots, engine_time, *_ = Message.map_stream(encoded_response_pdu)
      @security_parameters.engine_id = engine_id
      # sets the interval between sytem tyme and engine_time
      # takes timeout plus 2 seconds in account
      @engine_time_gap = (Time.now.to_i - (engine_time + @timeout + 2))
    end

    def encode(pdu, engine_time = (Time.now.to_i - @engine_time_gap))
      Message.encode(pdu, security_parameters: @security_parameters, 
                          engine_boots: @engine_boots,
                          engine_time: engine_time)
    end

    def decode(stream, security_parameters: @security_parameters)
      Message.decode(stream, security_parameters: security_parameters)
    end

  end

end
