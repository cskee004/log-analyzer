require "test_helper"
include ActionDispatch::TestProcess



class DashboardControllerTest < ActiveSupport::TestCase
  

  test "should validate the uploaded file" do
    wrong_file_name = fixture_file_upload('wrong-type.txt', 'application/octet-stream')
    wrong_file_content = fixture_file_upload('auth-test.log', 'text/plain')
    big_file = fixture_file_upload('auth-test-size.log', 'application/octet-stream')
    correct_file = fixture_file_upload('auth-test.log', 'application/octet-stream')

    log_import = LogImport.new

    f0 = log_import.validate_file(wrong_file_name)
    f1 = log_import.validate_file(wrong_file_content)
    f2 = log_import.validate_file(big_file)
    f3 = log_import.validate_file(correct_file)

    assert_equal [false, "Filename failed: wrong-type.txt"], f0
    assert_equal [false, "Content type failed: text/plain"], f1
    assert_equal [false, "File size too big: 2097152 bytes"], f2
    assert_equal [true, "All checks passed"], f3
  end

end

#'text/plain'