# frozen_string_literal: true
require 'forwardable'
module NETSNMP
  MAXREQUESTID = 2147483647
  # Abstracts the PDU base structure into a ruby object. It gives access to its varbinds.
  #
  class PDU
    class << self

      def decode(der)
        asn_tree = case der
        when String
          OpenSSL::ASN1.decode(der)
        when OpenSSL::ASN1::ASN1Data
          der
        else
          raise Error, "#{der}: unexpected data"
        end

        *headers, request = asn_tree.value

        version, community = headers.map(&:value)

        type = request.tag

        *request_headers, varbinds = request.value

        request_id, error_status, error_index  = request_headers.map(&:value).map(&:to_i)

        varbs = varbinds.value.map{|vb| Hash[[:oid, :value].zip vb.value] }

        new(type: type, headers: [version, community],
                        error_status: error_status,
                        error_index: error_index,
                        request_id: request_id, 
                        varbinds: varbs)
      end

      # factory method that abstracts initialization of the pdu types that the library supports.
      # 
      # @param [Symbol] type the type of pdu structure to build
      # 
      def build(type, **args)
        typ = case type
          when :get       then 0
          when :getnext   then 1
          #when :getbulk   then 5
          when :set       then 3
          when :response  then 2
          else raise Error, "#{type} is not supported as type"
        end
        new(args.merge(type: typ))
      end
    end

    def to_der
      to_asn.to_der
    end

    def to_asn
      request_id_asn = OpenSSL::ASN1::Integer.new( @request_id )
      error_asn = OpenSSL::ASN1::Integer.new( @error_status )
      error_index_asn = OpenSSL::ASN1::Integer.new( @error_index )

      varbind_asns = OpenSSL::ASN1::Sequence.new( @varbinds.map(&:to_asn) )

      request_asn = OpenSSL::ASN1::ASN1Data.new( [request_id_asn,
                                                  error_asn, error_index_asn,
                                                  varbind_asns], @type,
                                                  :CONTEXT_SPECIFIC )

      OpenSSL::ASN1::Sequence.new( [ *encode_headers_asn, request_asn ] )
    end

    attr_reader :varbinds, :error, :version,
                :type, :community, :request_id

    private

    def initialize(type: , headers: , 
                           request_id: nil, 
                           error_status: 0,
                           error_index: 0,
                           varbinds: [])
      @version, @community = headers
      @version = @version.to_i
      @error_status = error_status
      @error = check_error_status(error_status)
      @error_index  = error_index
      @type = type
      @varbinds = []
      add_varbinds(varbinds)
      @request_id = request_id || SecureRandom.random_number(MAXREQUESTID)
    end

    # Adds a request varbind to the pdu
    # 
    # @param [OID] oid a valid oid
    # @param [Hash] options additional request varbind options
    # @option options [Object] :value the value for the oid
    def add_varbind(oid: , **options)
      Array(oid).each do |single_oid|
        @varbinds << Varbind.new(single_oid, **options)
      end
    end
    alias_method :<<, :add_varbind

    def add_varbinds(varbinds)
      ## injects varbind with pdu error if any
      @varbinds << Varbind.new("1.3.6.1.6.3.15.1.1.7.0", value: @error) if @error
      varbinds.each{|v| add_varbind(v) }
    end

    def encode_headers_asn
      [ OpenSSL::ASN1::Integer.new( @version ),
        OpenSSL::ASN1::OctetString.new( @community ) ]
    end

    # http://www.tcpipguide.com/free/t_SNMPVersion2SNMPv2MessageFormats-5.htm#Table_219
    def check_error_status(status)
      return nil if status == 0
      case status
        when 1 then :response_pdu_too_big
        when 2 then :no_such_name
        when 3 then :bad_value
        when 4 then :read_only
        when 5 then :generic_error
        when 6 then :access_denied
        when 7 then :wrong_type
        when 8 then :wrong_length
        when 9 then :wrong_encoding
        when 10 then :wrong_value
        when 11 then :no_creation
        when 12 then :inconsistent_value
        when 13 then :resource_unavailable
        when 14 then :commit_failed
        when 15 then :undo_failed
        when 16 then :authorization_error
        when 17 then :not_writable
        when 18 then :inconsistent_name
        else
          "unknown_pdu_error_#{status}".to_sym
      end
    end
  end
end
