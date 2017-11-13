RSpec.describe NETSNMP::PDU do
  let(:encoded_get_pdu) { "0'\002\001\000\004\006public\240\032\002\002?*\002\001\000\002\001\0000\0160\f\006\b+\006\001\002\001\001\001\000\005\000" }
  let(:encoded_response_pdu) { "0+\002\001\000\004\006public\242\036\002\002'\017\002\001\000\002\001\0000\0220\020\006\b+\006\001\002\001\001\001\000\004\004test" }

  describe "#to_der" do
    let(:pdu_get){ described_class.build(:get,
                                         headers: [0, "public"] ,
                                         request_id: 16170,
                                         varbinds: [{oid: ".1.3.6.1.2.1.1.1.0"}]) }

    context "v1" do
      it { expect(pdu_get.to_der).to eq(encoded_get_pdu.b) }
    end
  end

  describe "#build" do
    it "#raises error" do
      expect { described_class.build(:ups, headers: [0, "public"])}.to raise_error(NETSNMP::Error, "ups is not supported as type")
    end
    it "checks error codes" do
      expect{ described_class.decode( 1 ) }.to raise_error(NETSNMP::Error, "1: unexpected data")
      expect( described_class.build(:response, headers: [0, ""], error_status: 1 ).varbinds[0].value ).to be(:response_pdu_too_big)
      expect( described_class.build(:response, headers: [0, ""], error_status: 2 ).varbinds[0].value ).to be(:no_such_name)
      expect( described_class.build(:response, headers: [0, ""], error_status: 3 ).varbinds[0].value ).to be(:bad_value)
      expect( described_class.build(:response, headers: [0, ""], error_status: 4 ).varbinds[0].value ).to be(:read_only)
      expect( described_class.build(:response, headers: [0, ""], error_status: 5 ).varbinds[0].value ).to be(:generic_error)
      expect( described_class.build(:response, headers: [0, ""], error_status: 6 ).varbinds[0].value ).to be(:access_denied)
      expect( described_class.build(:response, headers: [0, ""], error_status: 7 ).varbinds[0].value ).to be(:wrong_type)
      expect( described_class.build(:response, headers: [0, ""], error_status: 8 ).varbinds[0].value ).to be(:wrong_length)
      expect( described_class.build(:response, headers: [0, ""], error_status: 9 ).varbinds[0].value ).to be(:wrong_encoding)
      expect( described_class.build(:response, headers: [0, ""], error_status: 10 ).varbinds[0].value ).to be(:wrong_value)
      expect( described_class.build(:response, headers: [0, ""], error_status: 11 ).varbinds[0].value ).to be(:no_creation)
      expect( described_class.build(:response, headers: [0, ""], error_status: 12 ).varbinds[0].value ).to be(:inconsistent_value)
      expect( described_class.build(:response, headers: [0, ""], error_status: 13 ).varbinds[0].value ).to be(:resource_unavailable)
      expect( described_class.build(:response, headers: [0, ""], error_status: 14 ).varbinds[0].value ).to be(:commit_failed)
      expect( described_class.build(:response, headers: [0, ""], error_status: 15 ).varbinds[0].value ).to be(:undo_failed)
      expect( described_class.build(:response, headers: [0, ""], error_status: 16 ).varbinds[0].value ).to be(:authorization_error)
      expect( described_class.build(:response, headers: [0, ""], error_status: 17 ).varbinds[0].value ).to be(:not_writable)
      expect( described_class.build(:response, headers: [0, ""], error_status: 18 ).varbinds[0].value ).to be(:inconsistent_name)
      expect( described_class.build(:response, headers: [0, ""], error_status: "bla" ).varbinds[0].value ).to be(:unknown_pdu_error_bla)
    end
  end

  describe "#decoding pdus" do
    describe "v1" do
      let(:pdu_response) { described_class.decode(encoded_response_pdu) }
      it { expect(pdu_response.version).to be(0) }
      it { expect(pdu_response.community).to eq("public") }
      it { expect(pdu_response.request_id).to be(9999) }

      it { expect(pdu_response.varbinds.length).to be(1) }
      it { expect(pdu_response.varbinds[0].oid).to eq("1.3.6.1.2.1.1.1.0") } 
      it { expect(pdu_response.varbinds[0].value).to eq("test") }
    end
  end
end
