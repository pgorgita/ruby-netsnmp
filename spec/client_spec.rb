require_relative "support/request_examples"

RSpec.describe NETSNMP::Client do
  let(:host) { "localhost" }

  let(:device_options) { {
    peername: "localhost",
    port: SNMPPORT
  } }

  describe "v1" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) { {
        version: "1",
        community: "public"
      } }
      let(:get_oid) { "1.3.6.1.6.3.10.2.1.1.0" }
      let(:multi_get_oid) { ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.7.0"] }
      let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) { "1.3.6.1.2.1.1.3.0" } # sysUpTimeInstance
      let(:get_result) { {"1.3.6.1.6.3.10.2.1.1.0"=>:no_such_name} }
      let(:multi_get_result) { {"1.3.6.1.2.1.1.5.0"=>"DEVICE-192.168.1.1", "1.3.6.1.2.1.1.7.0"=>72} }
      let(:next_result) { {"1.3.6.1.2.1.1.6.0"=>"The Cloud"} }
      let(:walk_result) { {"1.3.6.1.2.1.1.1.0"=>"Device description",
                           "1.3.6.1.2.1.1.2.0"=>"1.3.6.1.4.1.3454",
                           "1.3.6.1.2.1.1.3.0"=>NETSNMP::Timetick.new(78171676),
                           "1.3.6.1.2.1.1.4.0"=>"The Owner",
                           "1.3.6.1.2.1.1.5.0"=>"DEVICE-192.168.1.1",
                           "1.3.6.1.2.1.1.6.0"=>"The Cloud",
                           "1.3.6.1.2.1.1.7.0"=>72,
                           "1.3.6.1.2.1.1.8.0"=>NETSNMP::Timetick.new(0)} }
      let(:set_oid_result) { 43 }
    end
  end
  describe "v2" do
    it_behaves_like "an snmp client" do
      let(:protocol_options) { {
        version: "2c",
        community: "public"
      } }
      let(:get_oid) { "1.3.6.1.2.1.4.31.1.1.4.1" }
      let(:multi_get_oid) { ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.7.0"] }
      let(:next_oid) { "1.3.6.1.2.1.1.5.0" }
      let(:walk_oid) { "1.3.6.1.2.1.1" }
      let(:set_oid) { "1.3.6.1.2.1.1.3.0" }
      let(:get_result) { {"1.3.6.1.2.1.4.31.1.1.4.1"=>:no_such_instance_1} }
      let(:multi_get_result) { {"1.3.6.1.2.1.1.5.0"=>"DEVICE-192.168.1.1", "1.3.6.1.2.1.1.7.0"=>72} }
      let(:next_result) { {"1.3.6.1.2.1.1.6.0"=>"The Cloud"} }
      let(:walk_result) { {"1.3.6.1.2.1.1.1.0"=>"Device description",
                           "1.3.6.1.2.1.1.2.0"=>"1.3.6.1.4.1.3454",
                           "1.3.6.1.2.1.1.3.0"=>NETSNMP::Timetick.new(78171676),
                           "1.3.6.1.2.1.1.4.0"=>"The Owner",
                           "1.3.6.1.2.1.1.5.0"=>"DEVICE-192.168.1.1",
                           "1.3.6.1.2.1.1.6.0"=>"The Cloud",
                           "1.3.6.1.2.1.1.7.0"=>72,
                           "1.3.6.1.2.1.1.8.0"=>NETSNMP::Timetick.new(0)} }
      let(:set_oid_result) { 43 }

    end
  end

  describe "v3" do
    let(:extra_options) { {} }
    let(:version_options) { {
      version: "3",
      context: "a172334d7d97871b72241397f713fa12",
    } }
    let(:get_oid) { "1.3.6.1.2.1.1.5.0" }
    let(:multi_get_oid) { ["1.3.6.1.6.3.10.2.1.1.0", "1.3.6.1.2.1.4.31.1.1.4.1", "1.3.6.1.4.1.2021.10.1.6.3", "1.3.7.1.2.1.2.2.1.7.1"] }
    let(:next_oid) { "1.3.6.1.7" }
    let(:set_oid) { "1.3.6.1.2.1.1.3.0" } # sysUpTimeInstance
    let(:walk_oid) { "1.3.6.1.2.1.1.9.1.3" }
    let(:get_result) { {"1.3.6.1.2.1.1.5.0"=>"tt"} }
    let(:multi_get_result) { {"1.3.6.1.2.1.4.31.1.1.4.1" => 22906399, 
                              "1.3.6.1.6.3.10.2.1.1.0" => "80001f888092c37021529f4647",
                              "1.3.6.1.4.1.2021.10.1.6.3" => "9f78043cf5c28f",
                              "1.3.7.1.2.1.2.2.1.7.1" => :no_such_instance_1} }
    let(:next_result) { {"1.3.6.1.7"=>:end_of_mib} }
    let(:walk_result) { { "1.3.6.1.2.1.1.9.1.3.1"=>"The SNMP Management Architecture MIB.",
                          "1.3.6.1.2.1.1.9.1.3.2"=>"The MIB for Message Processing and Dispatching.",
                          "1.3.6.1.2.1.1.9.1.3.3"=>"The management information definitions for the SNMP User-based Security Model.",
                          "1.3.6.1.2.1.1.9.1.3.4"=>"The MIB module for SNMPv2 entities",
                          "1.3.6.1.2.1.1.9.1.3.5"=>"The MIB module for managing TCP implementations",
                          "1.3.6.1.2.1.1.9.1.3.6"=>"The MIB module for managing IP and ICMP implementations",
                          "1.3.6.1.2.1.1.9.1.3.7"=>"The MIB module for managing UDP implementations",
                          "1.3.6.1.2.1.1.9.1.3.8"=>"View-based Access Control Model for SNMP." }}
    let(:set_oid_result) { 43 }
    context "with a no auth no priv policy" do
      let(:user_options) { { username: "unsafe", security_level: :noauth } }
      it_behaves_like "an snmp client" do
        let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        # why is this here? that variation/notification community causes the simulagtor to go down
        # until I find the origin of the issue and patched it with an appropriated community, this
        # is here so that I test the set call at least once, although I'm sure it'll work always
        # for v3
        describe "#set" do
          let(:extra_options) { { #community: "variation/notification", 
                                  context: "0886e1397d572377c17c15036a1e6c66" } }
          it "updates the value of the oid" do
            prev_value = subject.get(oid: set_oid).values.first
            expect(prev_value).to be_a(Integer)

            # without type
            subject.set(oid: set_oid, value: set_oid_result)
            expect(subject.get(oid: set_oid).values.first).to eq(set_oid_result)

            subject.set(oid: set_oid, value: prev_value)
          end
        end

      end
    end
    context "with an only auth policy" do
      context "speaking md5" do
        let(:user_options) { { username: "authmd5", security_level: :auth_no_priv, 
                               auth_password: "maplesyrup", auth_protocol: :md5 } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "speaking sha" do
        let(:user_options) { { username: "authsha", security_level: :auth_no_priv, 
                               auth_password: "maplesyrup", auth_protocol: :sha } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end

    end
    context "with an auth priv policy" do
      context "auth in md5, encrypting in des" do
        let(:user_options) { { username: "authprivmd5des", auth_password: "maplesyrup",
                               auth_protocol: :md5, priv_password: "maplesyrup",
                               priv_protocol: :des } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in des" do
        let(:user_options) { { username: "authprivshades", auth_password: "maplesyrup",
                               auth_protocol: :sha, priv_password: "maplesyrup",
                               priv_protocol: :des } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end

      context "auth in md5, encrypting in aes" do
        let(:user_options) { { username: "authprivmd5aes", auth_password: "maplesyrup",
                               auth_protocol: :md5, priv_password: "maplesyrup",
                               priv_protocol: :aes } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
      context "auth in sha, encrypting in aes" do
        let(:user_options) { { username: "authprivshaaes", auth_password: "maplesyrup",
                               auth_protocol: :sha, priv_password: "maplesyrup",
                               priv_protocol: :aes } }
        it_behaves_like "an snmp client" do
          let(:protocol_options) { version_options.merge(user_options).merge(extra_options) }
        end
      end
    end
  end

  describe "v3 timeout" do

    let(:user_options) { { username: "authprivmd5des", auth_password: "maplesyrup",
                           auth_protocol: :md5, priv_password: "maplesyrup",
                           priv_protocol: :des } }
    let(:version_options) { {
      host: "localhost",
      version: "3",
      retries: 5,
      context: "a172334d7d97871b72241397f713fa12",
      timeout: 0.0001,
    } }
    let(:options) { device_options.merge(version_options.merge(user_options)) }
    it "#get raises timeout error" do
      expect { described_class.new(options){|client| client.get("1.3.6") }}.to raise_error(Timeout::Error, "timeout after 0.0001 seconds(#5 retries)")
    end

  end

end
