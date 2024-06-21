import { logger, level } from '../../../config/logger.js';

class StripeService {
  createOrder(userId, amount, planType) {
    try {
      let razorpayInstance = new Razorpay({
        key_id: process.env.RAZORPAY_KEY_ID,
        key_secret: process.env.RAZORPAY_KEY_SECRET,
      });
      console.log('\n\n razorpayInstance', razorpayInstance);

      var options = {
        amount: 1000, // amount in the smallest currency unit
        currency: 'INR',
        receipt: 'order_rcptid_11',
        notes: planType,
      };

      razorpayInstance.orders.create(options, function (err, order) {
        console.log('\n\n Order created ::', order);
        // TODO: store the order in database
      });
    } catch (error) {
      logger.log(level.error, e);
    }
  }

  getPayment(id) {
    try {
      let fetchedPayment = razorpayInstance.payments.fetch(paymentId);
      console.log('\n\n fetchedPayment', fetchedPayment);
    } catch (error) {
      logger.log(level.error, e);
    }
  }

  getAllPayments(from = '2000-01-01', to = '2030-01-01') {
    try {
      razorpayInstance.payments.all(
        {
          from: '2016-08-01',
          to: '2016-08-20',
        },
        (error, response) => {
          if (error) {
            logger.log(level.error, e);
          } else {
            console.log('\n\n fetched payments', response);
          }
        }
      );
    } catch (error) {
      logger.log(level.error, e);
    }
  }
}
