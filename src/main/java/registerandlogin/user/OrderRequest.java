package registerandlogin.user;

import java.util.List;

public class OrderRequest {
    private String intent;
    private List<PurchaseUnit> purchase_units;

    // Getters and setters

    public String getIntent() {
		return intent;
	}

	public void setIntent(String intent) {
		this.intent = intent;
	}

	public List<PurchaseUnit> getPurchase_units() {
		return purchase_units;
	}

	public void setPurchase_units(List<PurchaseUnit> purchase_units) {
		this.purchase_units = purchase_units;
	}

	public static class PurchaseUnit {
        private Amount amount;

        // Getters and setters

        public Amount getAmount() {
			return amount;
		}

		public void setAmount(Amount amount) {
			this.amount = amount;
		}

		public static class Amount {
            private String currency_code;
            private String value;
			public String getCurrency_code() {
				return currency_code;
			}
			public void setCurrency_code(String currency_code) {
				this.currency_code = currency_code;
			}
			public String getValue() {
				return value;
			}
			public void setValue(String value) {
				this.value = value;
			}

            // Getters and setters
        }
    }
}
