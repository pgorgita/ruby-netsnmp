# frozen_string_literal: true
module NETSNMP
  # Main Entity, provides the user-facing API to communicate with SNMP Agents
  #
  # Under the hood it creates a "session" (analogous to the net-snmp C session), which will be used
  # to proxy all the communication to the agent. the Client ensures that you only write pure ruby and
  # read pure ruby, not concerning with snmp-speak like PDUs, varbinds and the like. 
  #
  #
  class Client
    RETRIES = 1

    # @param [Hash] options the options to needed to enable the SNMP client.
    # @option options [String, Integer, nil] :version the version of the protocol (defaults to 3).
    #    also accepts common known declarations like :v3, "v2c", etc
    # @option options [Integer] :retries number of retries for each failed PDU (after which it raise timeout error. Defaults to {RETRIES} retries)
    # @yield [client] the instantiated client, after which it closes it for use. 
    # @example Yielding a clinet
    #    NETSNMP::Client.new(host: "241.232.22.12") do |client|
    #      puts client.get(oid: "1.3.6.1.2.1.1.5.0")
    #    end
    #
    def initialize(**options)
      version = options[:version]
      version = case version 
        when Integer then version # assume the use know what he's doing
        when /v?1/ then 0 
        when /v?2c?/ then 1 
        when /v?3/, nil then 3
      end

      @retries = options.fetch(:retries, RETRIES)
      @session ||= version == 3 ? V3Session.new(options) : Session.new(options)
      if block_given?
        begin
          yield self
        ensure
          close
        end
      end
    end

    # Closes the inner section 
    def close
      @session.close
    end

    # Performs an SNMP GET Request
    #
    def get(oid_opts, &block)
      xet(oid_opts, :get, &block)
    end

    # Performs an SNMP GETNEXT Request
    # 
    def get_next(oid_opts, &block)
      xet(oid_opts, :getnext, &block)
    end

    # Perform a SNMP SET Request
    #
    def set(oid_opts, &block)
      xet(oid_opts, :set, &block)
    end

    # Perform a SNMP Walk (issues multiple subsequent GENEXT requests within the oid subtree)
    #
    # @param [String] oid the root oid from the subtree
    #
    # @return [Hash] the enumerator-collection of the oid-value pairs
    #
    def walk(oid: , &block)
      output = {}
      walkoid = oid
      req_type = :get
      loop do
        next_get = xet({oid: walkoid}, req_type, &block)
        value_is_symbol = next_get.values[0].is_a?(::Symbol)
        if req_type == :get
          req_type = :getnext
          next if value_is_symbol
        end
        walkoid = next_get.keys.last
        break if !walkoid.match(%r/\A#{oid}\./) || value_is_symbol
        output.merge!(next_get)
      end
      output
    end

    # Perform a SNMP GETBULK Request (performs multiple GETNEXT)
    #
    # @param [String] oid the first oid
    # @param [Hash] options the varbind options 
    # @option options [Integer] :errstat sets the number of objects expected for the getnext instance
    # @option options [Integer] :errindex number of objects repeating for all the repeating IODs. 
    #
    # @return [Enumerator] the enumerator-collection of the oid-value pairs
    #
    #def get_bulk(oid)
    #  request = @session.build_pdu(:getbulk, *oids)
    #  request[:error_status]  = options.delete(:non_repeaters) || 0
    #  request[:error_index] = options.delete(:max_repetitions) || 10
    #  response = @session.send(request)
    #  Enumerator.new do |y|
    #    response.varbinds.each do |varbind|
    #      y << [ varbind.oid, varbind.value ]
    #    end
    #  end
    #end

    private

    # Performs any SNMP Request returning {oid => value}
    #
    # will yield the PDU if block is given
    #
    # @see {NETSNMP::Varbind#new}
    #
    def xet(oid_opts, type = :get)
      pdu = handle_retries { @session.request(type, oid_opts) }
      yield pdu if block_given?
      Hash[pdu.varbinds.map{|v| [v.oid, v.value] }]
    end

    # Handles timeout errors by reissuing the same pdu until it runs out or retries.
    #
    def handle_retries
      retries = @retries
      begin
        yield
      rescue Timeout::Error => e
        raise e unless retries > 0
        retries -= 1
        retry
      end
    end

  end
end
