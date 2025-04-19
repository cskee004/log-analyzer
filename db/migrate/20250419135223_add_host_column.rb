class AddHostColumn < ActiveRecord::Migration[8.0]
  def change
    add_column :events, :host, :string
  end
end
