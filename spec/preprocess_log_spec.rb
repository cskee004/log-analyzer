require "spec_helper"
require "preprocess_log"

example_1 = "Mar 31 10:36:28 ip-10-77-20-248 sshd[19551]: error: maximum authentication attempts exceeded for root from 122.191.89.89 port 37753 ssh2 [preauth]" #3903
example_2 = "Mar 31 11:06:50 ip-10-77-20-248 sshd[19710]: error: maximum authentication attempts exceeded for invalid user ajay from 42.184.142.151 port 47882 ssh2 [preauth]" #3932

describe "Preprocess log" do
  describe "parse example 1" do
    
    it "returns hash containing meta data from example 1 " do
      result = parse_error_line(example_1, 3903)
      expected = 
      {
        Line_number: 3903, 
        Date: "Mar 31", 
        Time: "10:36:28", 
        Host: "ip-10-77-20-248", 
        PID: "19551", 
        Message: "error: maximum authentication attempts exceeded",  
        User: "root", 
        Source_IP: "122.191.89.89", 
        Source_port: "37753", 
      }
      expect(result).to eq(expected)
    end

    xit "returns hash containing meta data from example 2 " do
      result = parse_error_line(example_2, 3932)
      expected = 
      {
        Line_number: 3932, 
        Date: "Mar 31", 
        Time: "11:06:50", 
        Host: "ip-10-77-20-248", 
        PID: "19710", 
        Message: "error: maximum authentication attempts exceeded", 
        User: "ajay",  
        Source_IP: "42.184.142.151", 
        Source_port: "47882", 
      }
      expect(result).to eq(expected)
    end
    
  end
end
