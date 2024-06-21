import { Router } from "express";
import { authMiddleware } from "../shared/middleweres/auth.middlewere.js";
import {makePayment, createCustomer, getAllCustomer, getCustomer, createPaymentMethod, getAllPaymentMethod, getPaymentMethod, AttachPaymentMethod, detachPaymentMethod, getAllPriceList, updatePrice, cancelTrial, AddPayId, updateCustomer, getInvoices } from '../controllers/payment.controller.js';

const routes = new Router();
const Path = {
    makePayment: '/make-payment',

    addPayId: '/addPayId',

    makeSchedulePayment: '/make-schedulePayment',

    createCustomer: '/create-customer',
    getAllCustomer: '/getAll-customer',
    getCustomer: '/get-customer/:customerId',

    createPaymentMethod: '/create-paymentMethod',
    getAllPaymentMethod: '/getAll-paymentMethod/:type',
    getPaymentMethod: '/getPaymentMethod/:paymentMethodId',
    attachPaymentMethod: '/attachPaymentMethod/:paymentMethodId',
    detachPaymentMethod: '/detachPaymentMethod/:paymentMethodId',

    getAllPriceList: '/getAll-priceList',
    updatePrice: '/update-price/:priceId',
    cancelTrial: '/cancel-trial/:subscribeScheduleId',

    updateCustomer: '/updateCustomer',
    getInvoices: '/getInvoices',
};

// Auth Token Gateway
routes.use(authMiddleware);

routes.post(Path.makePayment, makePayment);

routes.post(Path.addPayId, AddPayId);

routes.post(Path.createCustomer, createCustomer);
routes.get(Path.getAllCustomer, getAllCustomer);
routes.get(Path.getCustomer, getCustomer);
routes.post(Path.getInvoices, getInvoices);

routes.post(Path.createPaymentMethod, createPaymentMethod);
routes.get(Path.getAllPaymentMethod, getAllPaymentMethod);
routes.get(Path.getPaymentMethod, getPaymentMethod);
routes.put(Path.attachPaymentMethod, AttachPaymentMethod);
routes.put(Path.detachPaymentMethod, detachPaymentMethod);

routes.get(Path.getAllPriceList, getAllPriceList);

routes.put(Path.updatePrice, updatePrice);

routes.delete(Path.cancelTrial, cancelTrial);

routes.put(Path.updateCustomer, updateCustomer);
export default routes;
