class CreateTraces < ActiveRecord::Migration[8.0]
  def change
    create_table :traces do |t|
      t.string   :trace_id,   null: false
      t.string   :agent_id,   null: false
      t.string   :task_name,  null: false
      t.datetime :start_time, null: false
      t.integer  :status,     null: false, default: 0

      t.timestamps
    end

    add_index :traces, :trace_id,  unique: true
    add_index :traces, :agent_id
    add_index :traces, :status
    add_index :traces, :start_time
  end
end
