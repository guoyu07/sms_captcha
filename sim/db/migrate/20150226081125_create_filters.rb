class CreateFilters < ActiveRecord::Migration
  def change
    create_table :filters do |t|
      t.string :f_vpnip
      t.string :f_phone
      t.string :f_user

      t.timestamps null: false
    end
  end
end
