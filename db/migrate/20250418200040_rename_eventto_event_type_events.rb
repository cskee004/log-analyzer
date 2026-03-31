class RenameEventtoEventTypeEvents < ActiveRecord::Migration[8.0]
  def change
    rename_column :events, :event, :event_type
  end
end
