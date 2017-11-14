RSpec.shared_examples "an ASN1 encoder/decoder" do |value, value_type, object, oid, varbind_der|

  let(:from_object) { described_class.new(oid, value: object)}
  let(:asn_tree) { OpenSSL::ASN1.decode(varbind_der) }
  let(:from_asn) { described_class.new(asn_tree.value.first, value: asn_tree.value.last).value }
  let(:from_val_type) { described_class.new(oid, type: value_type, value: value) }

  context "from Object" do
    it "#value matches object" do
      expect(from_object.value).to eq(from_asn)
    end
    it "#to_der matches varbind_der" do
      expect(from_object.to_der).to eq(varbind_der)
    end
  end
  context "from value and type" do
    it "#value matches object" do
      expect(from_val_type.value).to eq(from_asn)
    end
    it "#to_der matches varbind_der" do
      expect(from_val_type.to_der).to eq(varbind_der)
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

end

RSpec.describe NETSNMP::Varbind do

  context "initialize with" do
    it "#unsupported asn tag raises error" do
      wrong_asn = OpenSSL::ASN1.decode("0\a\x06\x03+\x06\x00H\x00".b)
      expect { described_class.new(wrong_asn.value.first, value: wrong_asn.value.last)}.to raise_error(NETSNMP::Error, "unsupported varbind tag:8")
    end
    it "#unsupported oid raises error" do
      expect { described_class.new("0", value: nil)}.to raise_error(NETSNMP::Error, "invalid OBJECT ID: missing second number")
    end
    it "#unknown tag class is symbolysed" do
      asn = OpenSSL::ASN1::ASN1Data.new("test", 99, :PRIVATE)
      expect( described_class.new("1.3.6.88", value: asn).value ).to eq(:private_99_test)
    end
    it "#specific context tag class is symbolysed" do
      asn = OpenSSL::ASN1::ASN1Data.new("", 0, :CONTEXT_SPECIFIC)
      expect( described_class.new("1.3.6.89", value: asn).value ).to eq(:no_such_instance_0)
    end
  end

  describe "usmStats oids" do
    let(:asn_counter) { OpenSSL::ASN1::ASN1Data.new("\xff".b, 6, :APPLICATION) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.1.0", value: asn_counter).value ).to eq(:unsupported_security_levels_255) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.2.0", value: asn_counter).value ).to eq(:not_in_time_windows_255) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.3.0", value: asn_counter).value ).to eq(:unknown_user_names_255) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.4.0", value: asn_counter).value ).to eq(:unknown_engineid_255) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.5.0", value: asn_counter).value ).to eq(:wrong_digests_255) }
    it { expect( described_class.new("1.3.6.1.6.3.15.1.1.6.0", value: asn_counter).value ).to eq(:decryption_errors_255) }
  end

  subject { described_class.new(".1.3.6.1.0", value: "1.3.6", type: :oid) }

  describe "oid #to_der" do
    it { expect(subject.to_der).to eq("0\n\x06\x04+\x06\x01\x00\x06\x02+\x06".b) }
  end
  describe "oid #to_s" do
    it { expect(subject.to_s).to end_with(" @oid=1.3.6.1.0 @value=1.3.6>") }
  end

  describe "opaque #to_der" do
    it { expect(described_class.new(".1.3.6.1.4.0", value: "test", type: :opaque).to_der).to eq("0\r\x06\x05+\x06\x01\x04\x00D\x04test".b) }
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

