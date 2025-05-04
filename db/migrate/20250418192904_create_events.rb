class CreateEvents < ActiveRecord::Migration[8.0]
  def change
    create_table :events do |t|
      t.string :event, null: false
      t.string :date
      t.string :time
      t.string :pid
      t.string :message
      t.string :user
      t.string :source_ip
      t.string :source_port
      t.string :directory
      t.string :command
      t.string :key
      t.timestamps
    end
  end
end
