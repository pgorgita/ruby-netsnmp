RSpec.shared_examples "an snmp client" do
  let(:device_options) { {
    host: "localhost",
    port: SNMPPORT
  } }
  let(:protocol_options) { { } } 
  let(:extra_options) { { } }
  let(:options) { protocol_options.merge(device_options).merge(extra_options) }

  subject { described_class.new(options) }

  describe "#get" do
    let(:value) { subject.get(oid: get_oid) }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq(get_result)
    end
  end

  describe "#get(multi_varbind)" do
    let(:value) { subject.get(oid: multi_get_oid) }
    it "fetches the varbinds for a given oid" do
      expect(value).to eq(multi_get_result)
    end
  end

  describe "#get_next" do
    let(:value) { subject.get_next(oid: get_oid) }
    it "fetches the varbinds for the next oid" do
      expect(value).to eq(next_result)
    end
  end

  describe "#walk" do
    let(:value) { subject.walk(oid: walk_oid) }
    it "fetches the varbinds for the next oid" do
      expect(value).to eq(walk_result)
    end
  end

end
