RSpec.describe NETSNMP::Session do
  let(:options) { {
    version: '2c', 
    context: "public",
    port: SNMPPORT
  } }
  subject { described_class.new({host: 'localhost'}.merge(options)) }
  after { subject.close }
  it "#unsupported version raises error" do
    expect { described_class.new(host: 'localhost', version: '4c') }.to raise_error(NETSNMP::Error, "unsupported snmp version (4c)")
  end
end
