import assert from "node:assert/strict";
import test from "node:test";
import { isActiveGumroadPurchase } from "../app/license";

const PRODUCT = "expected-product";

test("accepts only an active purchase for the configured product", () => {
  assert.equal(
    isActiveGumroadPurchase(
      { success: true, purchase: { product_id: PRODUCT } },
      PRODUCT,
    ),
    true,
  );
  assert.equal(
    isActiveGumroadPurchase(
      { success: true, purchase: { product_id: "another-product" } },
      PRODUCT,
    ),
    false,
  );
  assert.equal(
    isActiveGumroadPurchase(
      { success: true, purchase: { product_id: PRODUCT, refunded: true } },
      PRODUCT,
    ),
    false,
  );
  assert.equal(
    isActiveGumroadPurchase(
      { success: true, purchase: { product_id: PRODUCT, disputed: true } },
      PRODUCT,
    ),
    false,
  );
  assert.equal(isActiveGumroadPurchase({ success: false }, PRODUCT), false);
});
