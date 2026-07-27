export type GumroadLicenseResponse = {
  success?: boolean;
  purchase?: {
    product_id?: string;
    refunded?: boolean;
    disputed?: boolean;
    chargebacked?: boolean;
  };
};

export function isActiveGumroadPurchase(
  result: GumroadLicenseResponse,
  productId: string,
): boolean {
  const purchase = result.purchase;
  return Boolean(
    result.success &&
      purchase?.product_id === productId &&
      !purchase.refunded &&
      !purchase.disputed &&
      !purchase.chargebacked,
  );
}
