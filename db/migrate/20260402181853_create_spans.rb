class CreateSpans < ActiveRecord::Migration[8.0]
  def change
    create_table :spans do |t|
      t.string   :trace_id,       null: false
      t.string   :span_id,        null: false
      t.string   :parent_span_id
      t.string   :span_type,      null: false
      t.datetime :timestamp,      null: false
      t.string   :agent_id,       null: false
      t.json     :metadata,       null: false, default: {}

      t.timestamps
    end

    add_index :spans, :trace_id
    add_index :spans, [:trace_id, :span_id], unique: true
    add_index :spans, :span_type
    add_index :spans, :agent_id

    add_foreign_key :spans, :traces, column: :trace_id, primary_key: :trace_id
  end
end
