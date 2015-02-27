class CreateMsgs < ActiveRecord::Migration
  def change
    create_table :msgs do |t|
      t.string :vpnip
      t.string :vpnmac
      t.string :phone
      t.string :sms

      t.timestamps null: false
    end
  end
end
