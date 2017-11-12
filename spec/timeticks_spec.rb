# from https://ask.wireshark.org/questions/14002/how-to-decode-timeticks-hundreds-seconds-to-readable-date-time
RSpec.describe NETSNMP::Timetick do
  subject { described_class.new(1525917187) }

  describe "sums as an integer" do
    it { expect((1 + subject).to_i).to be(1525917188) }
  end

  describe "as an embedded string" do
    it { expect(subject.to_s).to eq("Timeticks: (1525917187) 176 days, 14:39:31.87") }
  end

  describe "subtracts as an integer" do
    it { expect((1525917188 - subject).to_i).to be(1) }
  end

  describe "multiplies as an integer" do
    it { expect((10 * subject).to_i).to be(15259171870) }
  end

  describe "divides as an integer" do
    it { expect((1525917187 / subject).to_i).to be(1) }
  end

end
