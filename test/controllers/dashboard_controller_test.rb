require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  test "should get index" do
    get dashboard_index_url
    assert_response :success
  end

  test "should get upload" do
    get dashboard_upload_url
    assert_response :success
  end

  test "should get summary" do
    get dashboard_summary_url
    assert_response :success
  end

  test "should get graph" do
    get dashboard_graph_url
    assert_response :success
  end

  test "should get table" do
    get dashboard_table_url
    assert_response :success
  end
end
