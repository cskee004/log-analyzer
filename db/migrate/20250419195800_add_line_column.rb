class AddLineColumn < ActiveRecord::Migration[8.0]
  def change
    add_column :events, :line_number, :string
  end
end
