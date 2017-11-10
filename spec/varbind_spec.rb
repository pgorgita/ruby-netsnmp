RSpec.shared_examples "an ASN1 encoder/decoder" do |value, value_type, object, oid, varbind_der|

  let(:from_object) { described_class.new(oid, value: object).to_der }
  let(:asn_tree) { OpenSSL::ASN1.decode(varbind_der) }
  let(:wrong_asn) { OpenSSL::ASN1.decode("0\a\x06\x03+\x06\x00H\x00".b) }
  let(:from_asn) { described_class.new(asn_tree.value.first, value: asn_tree.value.last).value }
  let(:from_val_type) { described_class.new(oid, type: value_type, value: value).value }

  context "from Object" do
    it "#to_der matches varbind_der" do
      expect(from_object).to eq(varbind_der)
    end
  end
  context "from ASN" do
    it "#value matches object" do
      expect(from_asn).to eq(object)
    end
  end
  context "from value and type" do
    it "#value matches object" do
      expect(from_val_type).to eq(object)
    end
  end
  context "from object and unsupported type" do
    it "#raises error" do
      expect { described_class.new(oid, value: object, type: :fail) }.to raise_error(NETSNMP::Error, /unsupported varbind type:/)
    end
  end
  context "from unsupported object" do
    it "#raises error" do
      expect { described_class.new(oid, value: Time.now) }.to raise_error(NETSNMP::Error, /unsupported varbind value:/)
    end
  end
  context "from unsupported asn tag" do
    it "#raises error" do
      expect { described_class.new(wrong_asn.value.first, value: wrong_asn.value.last)}.to raise_error(NETSNMP::Error, /unknown asn tag:/)
    end
  end
end

RSpec.describe NETSNMP::Varbind do

  subject { described_class.new(".1.3.6.1.0", value: "a") }

  describe "#to_der" do
    it { expect(subject.to_der).to eq("0\t\x06\x04+\x06\x01\x00\x04\x01a".b) }
  end
  describe "#to_s" do
    it { expect(subject.to_s).to end_with(" @oid=1.3.6.1.0 @value=a>") }
  end
  describe "#to_asn" do
    it { expect(subject.to_asn.to_der).to eq("0\t\x06\x04+\x06\x01\x00\x04\x01a".b) }
  end

  describe "initialized with ipaddress" do
    include_examples "an ASN1 encoder/decoder",
                     "10.11.104.2",
                     :ipaddress,
                     IPAddr.new("10.11.104.2"),
                     ".1.3.6.1.4.1.2011.6.3.1.1.0",
                     "0\x14\x06\f+\x06\x01\x04\x01\x8F[\x06\x03\x01\x01\x00@\x04\n\vh\x02".b

  end
  describe "initialized with timeticks" do
    include_examples "an ASN1 encoder/decoder",
                     1,
                     :timetick,
                     NETSNMP::Timetick.new(1),
                     ".1.3.6.1.2.1.1.3.0",
                     "0\x10\x06\b+\x06\x01\x02\x01\x01\x03\x00C\x04\x00\x00\x00\x01".b

  end
  describe "initialized with string" do
    include_examples "an ASN1 encoder/decoder",
                     "The SNMP Management Architecture MIB.",
                     :string,
                     "The SNMP Management Architecture MIB.",
                     "1.3.6.1.2.1.1.9.1.3.1",
                     "03\x06\n+\x06\x01\x02\x01\x01\t\x01\x03\x01\x04%The SNMP Management Architecture MIB.".b

  end
  describe "initialized with boolean(true)" do
    include_examples "an ASN1 encoder/decoder",
                     true,
                     :boolean,
                     true,
                     "1.3.6.1.2.1.1.9.1.3.1",
                     "0\x0F\x06\n+\x06\x01\x02\x01\x01\t\x01\x03\x01\x01\x01\xFF".b

  end
  describe "initialized with boolean(false)" do
    include_examples "an ASN1 encoder/decoder",
                     false,
                     :boolean,
                     false,
                     "1.3.6.1.2.1.1.9.1.3.1" ,
                     "0\x0F\x06\n+\x06\x01\x02\x01\x01\t\x01\x03\x01\x01\x01\x00".b

  end
  describe "initialized with integer" do
    include_examples "an ASN1 encoder/decoder",
                     257,
                     :integer,
                     257,
                     "1.3.6.1.2.1.1.7.0",
                     "0\x0E\x06\b+\x06\x01\x02\x01\x01\a\x00\x02\x02\x01\x01".b

  end

  describe "initialized with oid" do
    include_examples "an ASN1 encoder/decoder",
                     "1.3.6",
                     :oid,
                     "1.3.6",
                     ".1.3.6.1.4.1.2011.6.3.0",
                     "0\x13\x06\n+\x06\x01\x04\x01\x8F[\x06\x03\x00\x04\x051.3.6".b

  end

  describe "initialized with nil" do
    include_examples "an ASN1 encoder/decoder",
                     nil,
                     :nil,
                     nil,
                     ".1.3.6.1.4.1.2011.6.3.1.0",
                     "0\x0F\x06\v+\x06\x01\x04\x01\x8F[\x06\x03\x01\x00\x05\x00".b

  end

  describe "initialized with big number" do
    include_examples "an ASN1 encoder/decoder",
                     257,
                     :integer,
                     OpenSSL::BN.new(257),
                     ".1.3.6.1.4.1.2011.6.3.1.0",
                     "0\x11\x06\v+\x06\x01\x04\x01\x8F[\x06\x03\x01\x00\x02\x02\x01\x01".b

  end

end
