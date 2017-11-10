require 'celluloid/io'
require_relative "../support/request_examples"
require_relative '../support/celluloid'

RSpec.describe "with cellulloid", type: :celluloid do
  include CelluloidHelpers
  let(:user_options) { { username: "authprivmd5des", auth_password: "maplesyrup",
                         auth_protocol: :md5, priv_password: "maplesyrup",
                         priv_protocol: :des } }

  let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
  let(:multi_get_oid) { ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.9.1.3.1"] }
  let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
  let(:set_oid) { "1.3.6.1.2.1.1.3.0" } # sysUpTimeInstance
  let(:walk_oid) { "1.3.6.1.2.1.1.9.1.3" }
  let(:get_result) { {"1.3.6.1.2.1.1.5.0"=>"tt"} }
  let(:multi_get_result) { {"1.3.6.1.2.1.1.5.0"=>"tt", "1.3.6.1.2.1.1.9.1.3.1"=>"The SNMP Management Architecture MIB."} }
  let(:next_result) { {"1.3.6.1.2.1.1.6.0"=>"KK12 (edit /etc/snmp/snmpd.conf)"} }
  let(:walk_result) { {"1.3.6.1.2.1.1.9.1.3.1"=>"The SNMP Management Architecture MIB.",
                       "1.3.6.1.2.1.1.9.1.3.2"=>"The MIB for Message Processing and Dispatching.",
                       "1.3.6.1.2.1.1.9.1.3.3"=>"The management information definitions for the SNMP User-based Security Model.",
                       "1.3.6.1.2.1.1.9.1.3.4"=>"The MIB module for SNMPv2 entities",
                       "1.3.6.1.2.1.1.9.1.3.5"=>"The MIB module for managing TCP implementations",
                       "1.3.6.1.2.1.1.9.1.3.6"=>"The MIB module for managing IP and ICMP implementations",
                       "1.3.6.1.2.1.1.9.1.3.7"=>"The MIB module for managing UDP implementations",
                       "1.3.6.1.2.1.1.9.1.3.8"=>"View-based Access Control Model for SNMP." } }

  around(:each) do |example|
    within_io_actor { example.run }
  end
  let(:proxy) { CelluloidHelpers::Proxy.new("localhost", SNMPPORT) }
  after(:each) { proxy.close } 

  it_behaves_like "an snmp client" do
    subject { NETSNMP::Client.new(options) }
    let(:device_options) { { proxy: proxy } }
    let(:protocol_options) { user_options }
    let(:extra_options) { { version: 3, context: "a172334d7d97871b72241397f713fa12" } }
  end
  
end
