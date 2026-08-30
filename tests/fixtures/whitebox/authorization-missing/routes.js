const router = require("express").Router();

router.get("/api/invoices/:id", requireInvoiceOwner, getInvoice);
router.delete("/api/invoices/:id", requireInvoiceOwner, deleteInvoice);
router.patch("/api/invoices/:id", updateInvoice);
