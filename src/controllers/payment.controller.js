import Stripe from 'stripe';
import moment from "moment";
import HTTPStatus from "http-status";
import {logger, level} from '../config/logger.js';
import User from "../models/user.model.js";
import PaymentMethod from "../models/payment_method.model.js";
import {beautify} from '../shared/utils/utility.js';
import messages from "../shared/constant/messages.const.js";
import {badRequestError, okResponse, paramMissingError, internalServerError, okResponseDiff} from "../shared/utils/utility.js";
import Payment from "../models/payment.model.js";
import { returnOnNotExist } from "../shared/services/database/query.service.js";
import { v4 as uuidv4 } from 'uuid';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export const makePayment = async (req, res) => {
    try {
            let data = req.body;
            const userId = req['currentUserId'];

            const user = await User.get({_id: userId});
            const customerId= user[0]?.customer_id;
            
            let is_trial_used= user[0]?.is_trial_used;
            let is_trial_running= user[0]?.is_trial_running;


            // if(!customerId) {
            //     return okResponse(res, messages.payment_attach_fail);
            // }

            // if (!data.paymentMethodId) {
            //     logger.log(level.info, 'makePayment payment_method found error');
            //     return paramMissingError(res, messages.missing_key.replace("{dynamic}", "payment_method"));
            // }
            
            if (!data.priceId) {
                logger.log(level.info, 'makePayment priceId found error');
                return paramMissingError(res, messages.missing_key.replace("{dynamic}", "priceId"));
            }
           
            if(data.is_schedule) { 
                const price = await stripe.prices.retrieve(data.priceId)
                console.log("price subscriptionSchedule::",price)

                let  interval;
                let  intervalCount;
                if (price) {
                    if (price.recurring) {
                         interval = price.recurring.interval;
                         intervalCount = price.recurring.interval_count || 1;
                    }else{
                        return paramMissingError(res, messages.replace("{dynamic}", "Price Recurring Not Found"));
                    }
                }else{
                    return paramMissingError(res, messages.replace("{dynamic}", "Price Not Found"));
                }
                if(is_trial_used===true){

                     const subscriptionSchedule = await stripe.subscriptionSchedules.create({
                        customer: user[0]?.customer_id,
                        start_date: moment().unix(),
                        end_behavior: 'release',
                        default_settings:{
                            collection_method:"charge_automatically"
                        },
                        phases: [
                            {
                                items: [
                                    {
                                        price: data.priceId,
                                        quantity: 1,
                                    },
                                ],
                                iterations: intervalCount,
                                default_payment_method: data.paymentMethodId,    
                            },
                        ],
                       
                    },)
                    if(subscriptionSchedule){

                        let start_Date = subscriptionSchedule.current_phase.start_date;
                        let startDate  =  moment.unix(start_Date);
                        let  planStartDate =  moment(startDate);

                        let end_Date = subscriptionSchedule.current_phase.end_date;
                        let endDate =  moment.unix(end_Date);
                        
                        let activePlanEndDate;
                        let firstCycleDate,secondCycleDate,thirdCycleDate,fourCycleDate,fiveCycleDate,sixCycleDate;

                        if(interval==="month" && intervalCount==1){
                            activePlanEndDate = endDate;
                        }
                        else if(interval==="month" && intervalCount==3){
                            firstCycleDate = getDateAfterThreeMonths(start_Date);
                           
                            const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)
                            
                            secondCycleDate = getDateAfterThreeMonths(firstCycleEndDate);
                            
                            const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)
                            
                            thirdCycleDate = getDateAfterThreeMonths(secondCycleEndDate);
                           
                            const thirdCycleEndDate = isoStringToUnixTimeStamp(thirdCycleDate)

        
                            let firstCyclePlanDate=moment(firstCycleDate);
                            let secondCyclePlanDate=moment(secondCycleDate);
                            let thirdCyclePlanDate=moment(thirdCycleDate);
                                
                                if (planStartDate.isSameOrBefore(firstCyclePlanDate)) {
                                    activePlanEndDate = firstCyclePlanDate;
        
                                } else if (planStartDate.isSameOrBefore(secondCyclePlanDate)) {
                                    activePlanEndDate = secondCyclePlanDate;
                                    
                                } else if (planStartDate.isSameOrBefore(thirdCyclePlanDate)) {
                                    activePlanEndDate = thirdCyclePlanDate;
                                }  
                        }
                        else if(interval==="month" && intervalCount==6){
                            firstCycleDate = getDateAftersixMonths(start_Date);
                            const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)
        
                            secondCycleDate = getDateAftersixMonths(firstCycleEndDate);
                            const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)
        
                            thirdCycleDate = getDateAftersixMonths(secondCycleEndDate);
                            const thirdCycleEndDate = isoStringToUnixTimeStamp(thirdCycleDate)
        
                            fourCycleDate = getDateAftersixMonths(thirdCycleEndDate);
                            const fourCycleEndDate = isoStringToUnixTimeStamp(fourCycleDate)
                            
                            fiveCycleDate = getDateAftersixMonths(fourCycleEndDate);
                            const fiveCycleEndDate = isoStringToUnixTimeStamp(fiveCycleDate)
        
                            sixCycleDate = getDateAftersixMonths(fiveCycleEndDate);
                        
                            let firstCyclePlanDate=moment(firstCycleDate);
                            let secondCyclePlanDate=moment(secondCycleDate);
                            let thirdCyclePlanDate=moment(thirdCycleDate);
                            let fourCyclePlanDate=moment(fourCycleDate);
                            let fiveCyclePlanDate=moment(fiveCycleDate);
                            let sixCyclePlanDate=moment(sixCycleDate);
                        
                                if (planStartDate.isSameOrBefore(firstCyclePlanDate)) {
                                    activePlanEndDate = firstCyclePlanDate;
        
                                } else if (planStartDate.isSameOrBefore(secondCyclePlanDate)) { 
                                    activePlanEndDate = secondCyclePlanDate;
                                    
                                } else if (planStartDate.isSameOrBefore(thirdCyclePlanDate)) { 
                                    activePlanEndDate = thirdCyclePlanDate;
                                }  
                                else if (planStartDate.isSameOrBefore(fourCyclePlanDate)) {
                                    activePlanEndDate = fourCyclePlanDate;
                                }
                                else if (planStartDate.isSameOrBefore(fiveCyclePlanDate)) {
                                    activePlanEndDate = fiveCyclePlanDate;
                                }
                                else if (planStartDate.isSameOrBefore(sixCyclePlanDate)) { 
                                    activePlanEndDate = sixCyclePlanDate;
                                }   
                        }
                        else if(interval==="year" && intervalCount==1){
                            activePlanEndDate = endDate;
                        }
                        else if(interval==="day" && intervalCount==1){
                            activePlanEndDate = endDate;
                        }
                
                        if(subscriptionSchedule?.id) {
                            const price = await stripe.prices.retrieve(data.priceId);
                            const product = await stripe.products.retrieve(price?.product);
                            const productName = product.name;

                            const payload = {
                                priceId: data.priceId,
                                paymentMethodId: data.paymentMethodId,
                                subscribeScheduleId: subscriptionSchedule?.id,
                                subscribeId: subscriptionSchedule?.subscription,
                                priceDetail: {
                                    price: price?.unit_amount,
                                    recurring: price?.recurring
                                },
                                user_id: userId,
                                current_phase: {   
                                    startDate: new Date(startDate).toISOString(),
                                    endDate: new Date(endDate).toISOString(),
                                    activePlanEndDate: new Date(activePlanEndDate).toISOString(),
                                },
                                is_schedule: data.is_schedule
                            };
                            const response = {
                                subscribeScheduleId : subscriptionSchedule?.id,
                                priceId : payload?.priceId,
                                current_phase : payload?.current_phase,
                                planName: productName || ""
                            };
                                await Payment.add(payload);
                                await User.update({_id: userId}, {is_schedule: data.is_schedule, is_plan_running:true});
                                return okResponse(res, messages.created.replace("{dynamic}", "PaymentSchedule"), response);
                        } else {
                            // return okResponse(res, messages.payment_fail);
                            return paramMissingError(res, messages.replace("{dynamic}", "SubscriptionSchedule Id Not Found"));
                        }
                    }
                    else{
                        return okResponse(res, messages.subscription_fail);
                    }
                }
                else{
                        // Calculate the trial end timestamp using Moment.js
                        // const trialEndTimestamp = moment().add(14, 'days').unix();
                        const trialEndTimestamp = moment().add(3, 'minutes').unix();
                        const subscriptionSchedule = await stripe.subscriptionSchedules.create({
                            customer: user[0]?.customer_id,
                            start_date: moment().unix(),
                            end_behavior: 'release',
                            default_settings:{
                                collection_method:"charge_automatically"
                            },
                            phases: [
                                {
                                    items: [
                                        {
                                            price: data.priceId,
                                            quantity: 1,
                                        },
                                    ],
                                    iterations: intervalCount,
                                    default_payment_method: data.paymentMethodId,
                                    trial_end: trialEndTimestamp,
                                
                                },
                            ],
                        
                        }, 
                        );
                        console.log("subscriptionSchedule::",subscriptionSchedule)
                        if(subscriptionSchedule){

                                let start_Date = subscriptionSchedule.current_phase.start_date;
                                let startDate  =  moment.unix(start_Date);
                                let  planStartDate =  moment(startDate);
                                  
                                let end_Date = subscriptionSchedule.current_phase.end_date;
                                let endDate =  moment.unix(end_Date);

                                let trial_End = subscriptionSchedule.phases[0].trial_end;
                                let trialEnd =  moment.unix(trial_End);
                                                        
                                let activePlanEndDate;
                                let firstCycleDate,secondCycleDate,thirdCycleDate,fourCycleDate,fiveCycleDate,sixCycleDate;

                                if(interval==="month" && intervalCount==1){
                                    activePlanEndDate = endDate;
                                }
                                else if(interval==="month" && intervalCount==3){
                                    firstCycleDate = getDateAfterThreeMonths(start_Date);
                                    const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)
                
                                    secondCycleDate = getDateAfterThreeMonths(firstCycleEndDate);
                                   
                                    const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)
            
                                    thirdCycleDate = getDateAfterThreeMonths(secondCycleEndDate);
                                    const thirdCycleEndDate = isoStringToUnixTimeStamp(thirdCycleDate)

                                    let firstCyclePlanDate=moment(firstCycleDate);
                                    let secondCyclePlanDate=moment(secondCycleDate);
                                    let thirdCyclePlanDate=moment(thirdCycleDate);
                                        
                                        if (planStartDate.isSameOrBefore(firstCyclePlanDate)) {     
                                            activePlanEndDate = firstCyclePlanDate;
                
                                        } else if (planStartDate.isSameOrBefore(secondCyclePlanDate)) {                                          
                                            activePlanEndDate = secondCyclePlanDate;
                                            
                                        } else if (planStartDate.isSameOrBefore(thirdCyclePlanDate)) {
                                            activePlanEndDate = thirdCyclePlanDate;
                                        }  
                                }
                                else if(interval==="month" && intervalCount==6){
                                    firstCycleDate = getDateAftersixMonths(start_Date);
                                    const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)
                
                                    secondCycleDate = getDateAftersixMonths(firstCycleEndDate);
                                    const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)
                
                                    thirdCycleDate = getDateAftersixMonths(secondCycleEndDate);
                                    const thirdCycleEndDate = isoStringToUnixTimeStamp(thirdCycleDate)
                
                                    fourCycleDate = getDateAftersixMonths(thirdCycleEndDate);
                                    const fourCycleEndDate = isoStringToUnixTimeStamp(fourCycleDate)
                                    
                                    fiveCycleDate = getDateAftersixMonths(fourCycleEndDate);
                                    const fiveCycleEndDate = isoStringToUnixTimeStamp(fiveCycleDate)
                
                                    sixCycleDate = getDateAftersixMonths(fiveCycleEndDate);
                                
                                    let firstCyclePlanDate=moment(firstCycleDate);
                                    let secondCyclePlanDate=moment(secondCycleDate);
                                    let thirdCyclePlanDate=moment(thirdCycleDate);
                                    let fourCyclePlanDate=moment(fourCycleDate);
                                    let fiveCyclePlanDate=moment(fiveCycleDate);
                                    let sixCyclePlanDate=moment(sixCycleDate);
                                
                                        if (planStartDate.isSameOrBefore(firstCyclePlanDate)) {
                                            activePlanEndDate = firstCyclePlanDate;
                
                                        } else if (planStartDate.isSameOrBefore(secondCyclePlanDate)) { 
                                            activePlanEndDate = secondCyclePlanDate;
                                            
                                        } else if (planStartDate.isSameOrBefore(thirdCyclePlanDate)) { 
                                            activePlanEndDate = thirdCyclePlanDate;
                                        }  
                                        else if (planStartDate.isSameOrBefore(fourCyclePlanDate)) {
                                            activePlanEndDate = fourCyclePlanDate;
                                        }
                                        else if (planStartDate.isSameOrBefore(fiveCyclePlanDate)) {
                                            activePlanEndDate = fiveCyclePlanDate;
                                        }
                                        else if (planStartDate.isSameOrBefore(sixCyclePlanDate)) { 
                                            activePlanEndDate = sixCyclePlanDate;
                                        }   
                                }
                                else if(interval==="year" && intervalCount==1){
                                    activePlanEndDate = endDate;
                                }
                                else if(interval==="day" && intervalCount==1){
                                    activePlanEndDate = endDate;
                                }

                        
                                if(subscriptionSchedule?.id) {
                                    const price = await stripe.prices.retrieve(data.priceId);
                                    const product = await stripe.products.retrieve(price?.product);
                                    
                                    const productName = product.name;
                                   
                                    const payload = {
                                        priceId: data.priceId,
                                        paymentMethodId: data.paymentMethodId,
                                        subscribeScheduleId: subscriptionSchedule?.id,
                                        subscribeId: subscriptionSchedule?.subscription,
                                        priceDetail: {
                                            price: price?.unit_amount,
                                            recurring: price?.recurring
                                        },
                                        user_id: userId,
                                        current_phase: {   
                                            startDate: new Date(startDate).toISOString(),
                                            endDate: new Date(endDate).toISOString(),
                                            trialEnd: new Date(trialEnd).toISOString(),
                                            activePlanEndDate: new Date(activePlanEndDate).toISOString(),
                                        },
                                        is_schedule: data.is_schedule
                                    };
                                    const response = {
                                        subscribeScheduleId : subscriptionSchedule?.id,
                                        priceId : payload?.priceId,
                                        current_phase : payload?.current_phase,
                                        planName: productName || ""
                                    };
                                        await Payment.add(payload);
                                                let isTrialRunning;

                                                let currentRunningDate=moment();

                                                let trialEnds = subscriptionSchedule.phases[0].trial_end;

                                                let trialEndsDate = moment.unix(trialEnds);

                                                const trialRunningDate=moment(trialEndsDate);


                                                if(currentRunningDate.isSameOrBefore(trialRunningDate)){
                                                    isTrialRunning = true;
                                                }
                                                else if(currentRunningDate.isAfter(trialRunningDate)){
                                                    isTrialRunning = false;
                                                }

                                        await User.update({_id: userId}, {is_schedule: data.is_schedule,is_trial_used:true,is_trial_running:isTrialRunning});
                                        return okResponse(res, messages.created.replace("{dynamic}", "Payment Schedule"), response);

                                } else {
                                        //return okResponse(res, messages.payment_fail);
                                        return paramMissingError(res, messages.replace("{dynamic}", "SubscriptionSchedule Id Not Found"));
                                    } 
                        }
                        else{
                            return okResponse(res, messages.subscription_fail);
                        }

                    }
            } else {
                    let actionUrl;
                    // if (!data.return_url) {
                    //     logger.log(level.info, 'makePayment return_url not found error');
                    //     return paramMissingError(res, messages.missing_key.replace("{dynamic}", "return_url"));
                    // }
                        var startDate = new Date(moment().format("MM/DD/YYYY")).getTime() / 1000;
                        let mandateId = referenceMandateId();

                        const price = await stripe.prices.retrieve(data.priceId);
                        console.log("priceLOGGGGG",price)
                        console.log("priceLOGGGGG////",price.unit_amount/100)
                        console.log("priceLOGGGGG***",price.unit_amount*100)
                        let interval;
                        let intervalCount;
                        let amount;
                        let currency;

                        if (price) {
                            // amount= price.unit_amount/100,
                            amount= price.unit_amount,
                            currency= price.currency
                            if (price.recurring) {
                                interval = price.recurring.interval;
                                intervalCount = price.recurring.interval_count || 1;
                            } 
                        }
                        const setupIntent = await stripe.setupIntents.create({
                            customer:customerId,  
                            payment_method_types:["card"],    
                            usage:"off_session",
                            //confirm:true,
                            payment_method:data.paymentMethodId,    
                            //return_url:data.return_url, 
                            description: 'Healing music services',
                            payment_method_options: {
                                card: {
                                mandate_options: {
                                    reference:mandateId,
                                    amount_type:"fixed",
                                    amount:amount,
                                    currency:currency,
                                    start_date:startDate,
                                    interval:interval,
                                    interval_count:intervalCount,
                                    supported_types:['india'],
                                },
                                
                                }
                            },              
                        });
                        console.log("setupIntent PRICE CHECKING",setupIntent)
                        console.log("setupIntent PRICE CHECKING mandate_options",setupIntent.payment_method_options.card.mandate_options)
                        console.log("setupIntent PRICE CHECKING amount",setupIntent.payment_method_options.card.mandate_options.amount)
                        if (setupIntent.next_action==="" || setupIntent.next_action===null){
                            actionUrl="";
                        }
                        else{
                            actionUrl=setupIntent.next_action.redirect_to_url.url;
                        }

                        if(setupIntent.id) {
                            const payload = {  
                                priceId: null,
                                user_id: userId,
                                expiry_time: "",
                                payment_id: setupIntent.id,
                                paymentDetail: setupIntent,
                                is_schedule: data.is_schedule
                            };
                            
                            await Payment.add(payload);                            
                            /* const price = await stripe.prices.retrieve(data.priceId);

                                if (price) {
                                    const product = await stripe.products.retrieve(price.product);
                                    const productName = product.name;
                                
                                    const startDate = new Date(); // Use the current date as the start date
                                
                                    let endDate = new Date(startDate);
                                
                                    if (price.recurring) {
                                        const interval = price.recurring.interval;
                                        const intervalCount = price.recurring.interval_count || 1;

                                        if (interval === "day") {
                                            endDate.setDate(endDate.getDate() + intervalCount);
                                        } else if (interval === "week") {
                                            endDate.setDate(endDate.getDate() + intervalCount * 7);
                                        } else if (interval === "month") {
                                            endDate.setMonth(endDate.getMonth() + intervalCount);
                                        } else if (interval === "year") {
                                            endDate.setFullYear(endDate.getFullYear() + intervalCount);
                                        }
                                    }
                                } else {
                                    return paramMissingError(res, messages.replace("{dynamic}", "Price Not Found"));
                                } */

                            const response = {
                                setupIntent:setupIntent,
                                subscribeScheduleId: null,
                                payment_method:payload.paymentDetail.payment_method,
                                customerId: customerId,
                                actionUrl: actionUrl || null,
                                // priceId: price.id,
                                // current_phase: {
                                //     startDate: startDate.toISOString(),
                                //     endDate: endDate.toISOString(),
                                // },
                                // planName: productName || ""
                            // planName: price?.metadata?.name || ""
                            };
                            return okResponse(res, messages.created.replace("{dynamic}", "Payment"), response);
                    } else {
                    return okResponse(res, messages.payment_fail);
                }
            }
        } catch (error) {
                logger.log(level.error,`Stripe create payment error${beautify(error.message)}`);
                return internalServerError(res, error)
            }
};

export const AddPayId = async (req, res) => {
    try {
        let data = req.body;
        const userId = req['currentUserId'];
        const { priceId = null, startDate = null, googlePayId = null, applePayId = null } = data;
        let endDate = null;
        if(priceId) {
            const priceDetail = await stripe.prices.retrieve(priceId);
            endDate = priceDetail?.recurring?.interval === "month" ? new Date(startDate).setMonth(new Date(startDate).getMonth() + priceDetail?.recurring?.interval_count) :
                new Date(startDate).setMonth(new Date(startDate).getMonth() + priceDetail?.recurring?.interval_count * 12);
        }
        const payload = {
            user_id: userId,
            priceId: priceId,
            googlePayId: googlePayId,
            applePayId: applePayId,
            is_schedule: false,
            current_phase: {
                startDate: new Date(startDate).toISOString(),
                endDate: new Date(endDate).toISOString()
            },
        };
        const paymentData = await Payment.add(payload);
        return okResponse(res, messages.created.replace("{dynamic}", "PayId"), paymentData);
    } catch (error) {
        logger.log(
            level.error,
            `add payId error${beautify(error.message)}`
        );
        return internalServerError(res, error)
    }
};

export const createCustomer = async (req, res) => {
    try {
        const filter = { _id: req['currentUserId'] };
        const userId = req['currentUserId'];

        const user = await User.get({_id: userId});
        if(user[0]?.customer_id) {
            logger.log(level.info, 'Customer is already exist');
            return badRequestError(res, messages.customer_exist);
        };

        if(user[0]?.name=== null || user[0]?.address === null || user[0]?.city=== null || user[0]?.state=== null || user[0]?.country=== null || user[0]?.zipcode=== null ){
            logger.log(level.info, 'Customer Address Details Required ');
            return paramMissingError(res,messages.is_required.replace('{dynamic}','Name And Address Details'),null);
        }
        const payload = {
            description: "",
            name: user[0]?.name,
            phone: user[0]?.phone_number || "",
            email: user[0]?.email || "",
            address:{
                line1: user[0]?.address,
                postal_code: user[0]?.zipcode,
                city: user[0]?.city,
                state: user[0]?.state,
                country: user[0]?.country,
            }
        };  

        const customer = await stripe.customers.create(payload);
        if (!customer.id) {
            logger.log(level.info, `createCustomer Error`);
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        await User.update(filter, { customer_id: customer.id });
        return okResponse(res, messages.created.replace("{dynamic}", "Customer"), customer);
    } catch (error) {
        logger.log(level.error, `Stripe create customer error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getAllCustomer = async (req,res) => {
    try {
        const { query } = req;
        const customers = await stripe.customers.list({
            limit: 100,
        });
        return okResponseDiff(res, messages.record_fetched, customers);
    } catch (error) {
        logger.log(level.error, `Admin getAllQuotes Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getCustomer = async (req, res) => {
    try {
        const { customerId } = req.params;
        const customer = await stripe.customers.retrieve(customerId);
        return okResponse(res, messages.record_fetched, customer);
    } catch (error) {
        logger.log(level.error, `Admin getAllQuotes Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const createPaymentMethod = async (req, res) => {
    try {
        const { body } = req;
        const { type = "", card, name = "" ,email="",description="" } = body;
        const { number = "", exp_month = "null", exp_year = "", cvc= "" } = card;
        const userId = req['currentUserId'];

        if (!type) {
            logger.log(level.info, 'createPaymentMethod type found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "type"));
        }

        if (!number) {
            logger.log(level.info, 'createPaymentMethod number found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "number"));
        }

        if (!exp_month) {
            logger.log(level.info, 'createPaymentMethod exp_month found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "exp_month"));
        }

        if (!exp_year) {
            logger.log(level.info, 'createPaymentMethod exp_year found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "exp_year"));
        }

        if (!cvc) {
            logger.log(level.info, 'createPaymentMethod cvc found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "cvc"));
        }

        const user = await User.get({_id: userId});
        if(!user[0]?.customer_id) {
            logger.log(level.info, 'Customer is not exist');
            return badRequestError(res, messages.customer_not_exist);
        }

        const paymentMethod = await stripe.paymentMethods.create({
            type: type,
            card: {
                number: number,
                exp_month: exp_month,
                exp_year: exp_year,
                cvc: cvc,
            },
            billing_details: {
                name: name,
                email: email,
            }
        });
        if (!paymentMethod.id) {
            logger.log(level.info, `createPaymentMethod Error`);
            return badRequestError(res, messages.invalid_input, null, HTTPStatus.NOT_FOUND)
        }
        const addPaymentMethod = await PaymentMethod.add({ userId, type, payment_Method_id: paymentMethod.id });
        logger.log(level.info, `createPaymentMethod Created: ${beautify(addPaymentMethod)}`);
        return okResponse(res, messages.created.replace("{dynamic}", "Payment Method"), paymentMethod);
    } catch (error) {
        logger.log(level.error, `Stripe create paymentMethod error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getAllPaymentMethod = async (req, res) => {
    try {
        const { type } = req.params;
        const userId = req['currentUserId'];
        const user = await User.get({_id: userId});
        if(user[0]?.customer_id) {
            const paymentMethods = await stripe.paymentMethods.list({
                customer: user[0]?.customer_id,
                type: type,
            });
            const data = paymentMethods?.data?.map(item => ({
                id : item?.id || "",
                name: item?.billing_details?.name,
                brand: item?.card?.brand,
                exp_month: item?.card?.exp_month,
                exp_year: item?.card?.exp_year,
                last4: item?.card?.last4,
                customer: item?.customer
            }));
            return okResponseDiff(res, messages.record_fetched, data);
        } else {
            return okResponse(res, messages.payment_attach_fail);
        }
    } catch (error) {
        logger.log(level.error, `Stripe create paymentMethod error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getPaymentMethod = async (req, res) => {
    try {
        const {paymentMethodId} = req.params;
        const paymentMethod = await stripe.paymentMethods.retrieve(paymentMethodId);
        let data = {};
        if (paymentMethod?.id) {
            data = {
                id: paymentMethod?.id || "",
                name: paymentMethod?.billing_details?.name,
                brand: paymentMethod?.card?.brand,
                exp_month: paymentMethod?.card?.exp_month,
                exp_year: paymentMethod?.card?.exp_year,
                last4: paymentMethod?.card?.last4,
                customer: paymentMethod?.customer
            };
        }
        return okResponse(res, messages.record_fetched, data);
    } catch (error) {
        logger.log(level.error, `Stripe create paymentMethod error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const AttachPaymentMethod = async (req, res) => {
    try {
        const { paymentMethodId } = req.params;
        const userId = req['currentUserId'];
        const user = await User.get({_id: userId});
        if(user[0]?.customer_id) {
            const paymentMethod = await stripe.paymentMethods.attach(
                paymentMethodId,
                {customer: user[0]?.customer_id}
            );
            return okResponse(res, messages.payment_attach, paymentMethod);
        } else {
            return okResponse(res, messages.payment_attach_fail);
        }
    } catch (error) {
        logger.log(level.error, `Stripe create paymentMethod error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const detachPaymentMethod = async (req, res) => {
    try {
        const { paymentMethodId } = req.params;
        const userId = req['currentUserId'];
        const user = await User.get({_id: userId});
        if(user[0]?.customer_id) {
            const paymentMethod = await stripe.paymentMethods.detach(paymentMethodId);
            return okResponse(res, messages.payment_detach, paymentMethod);
        } else {
            return okResponse(res, messages.payment_attach_fail);
        }
    } catch (error) {
        logger.log(level.error, `Stripe create paymentMethod error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const getAllPriceList = async (req,res) => {
    try {
            //NEW CODE
            const products = await stripe.products.list({ limit:100, active: true });
            const productList = await Promise.all(
                products.data.map(async (product) => {
                    const prices = await stripe.prices.list({ product: product.id,active: true });
                    prices?.data?.forEach(item => {
                        item.unit_amount = item.unit_amount / 100
                    });
                    product.prices = prices.data;
                    return product;
                }),
            );
            // console.log("products ==> ", productList)
            return okResponseDiff(res, messages.record_fetched, productList);

    } catch (error) {
        logger.log(level.error, `Admin getAllQuotes Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const updatePrice = async (req, res) => {
    try {
        const { priceId } = req.params;
        let data = req.body;
        if (!priceId) {
            logger.log(level.info, 'updatePrice priceId found error');
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "priceId"));
        }
        const price = await stripe.prices.update(priceId, {metadata: {recommended: data.recommended || false , name: data.name || ""}});
        return okResponse(res, messages.price_update, price);

        /*IF PRODUCT NAME NEEDS TO BE UPDATE FOR THAT THIS BELOW CODE NEED TO REPLACE
        const product = await stripe.products.update(
            'prod_OAHrwmiq3q3gNg',
            {name: "update queey hasbeen called test darshan"}
          );
        return okResponseDiff(res, messages.record_fetched, product); */
    } catch (error) {
        logger.log(level.error, `Admin getAllQuotes Error : ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const cancelTrial = async (req, res) => {
    try {
        const { params } = req;
        const { subscribeScheduleId } = params;
        const userId = req['currentUserId'];
        let start_Date,currentPlanEndDate,trial_End,current_phase={},start_date,end_date,trialEnd;
        let is_trial_cancel;
        
            const user = await User.get({_id: userId});
            is_trial_cancel = user[0].is_trial_cancel;
       
            const subscriptionScheduleData = await stripe.subscriptionSchedules.retrieve(subscribeScheduleId);
            
             start_Date =subscriptionScheduleData.phases[0].start_date;
             currentPlanEndDate =subscriptionScheduleData.phases[0].end_date;
             trial_End =subscriptionScheduleData.phases[0].trial_end;
        
             start_date = moment.unix(start_Date);
             end_date = moment.unix(currentPlanEndDate);
             trialEnd = moment.unix(trial_End);

            if(subscriptionScheduleData?.status === 'canceled'){
                current_phase ={
                    subscribeScheduleId:subscribeScheduleId,
                    startDate:start_date,
                    endDate:end_date,
                    trialEnd:trialEnd,
                    cancelledDate:null, //cancelledDate
                    activePlanEndDate:null, //activePlanEndDate
                    is_trial_cancel:is_trial_cancel,
                }
                // return okResponse(res, messages.deleted.replace("{dynamic}", "CancelTrail",current_phase));    
                return okResponse(res, messages.already_cancelled,current_phase);     
            }else{

                let price,interval,intervalCount;
                let firstCycleDate,secondCycleDate,thirdCycleDate,fourCycleDate,fiveCycleDate,sixCycleDate;
                let activePlanEndDate;

                
                let paymentDoc = await Payment.get({
                    user_id: userId,
                    $or: [{is_deleted: false}, {is_deleted: {$exists: false}}]
                    });
        
                    paymentDoc?.sort(function(a,b){
                        return b.created_at - a.created_at;
                        });
                    if(paymentDoc[0]?.is_schedule) {
                        
                        if (paymentDoc[0]?.priceId) {
                          price = await stripe.prices.retrieve(paymentDoc[0]?.priceId);
                            interval = price.recurring.interval || null;
                            intervalCount =price.recurring.interval_count || null;
                        }
                    }
                    
                const subscriptionSchedule = await stripe.subscriptionSchedules.cancel(subscribeScheduleId);
                let trial_End = subscriptionSchedule.phases[0].trial_end;

                
                if (!subscriptionSchedule) {
                    return badRequestError(res, messages.invalid_subscription_scheduleId);
                }

                let canceled_at = subscriptionSchedule.canceled_at;
                let cancelledDate = moment.unix(canceled_at);
                let cancelledPlanDate=moment(cancelledDate);

                if(interval==="month" && intervalCount==1){
                    activePlanEndDate = end_date;
                }
                else if(interval==="month" && intervalCount==3){

                    firstCycleDate = getDateAfterThreeMonths(start_Date);
                    const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)

                    secondCycleDate = getDateAfterThreeMonths(firstCycleEndDate);
                    const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)

                    thirdCycleDate = getDateAfterThreeMonths(secondCycleEndDate);

                    let firstCyclePlanDate=moment(firstCycleDate);
                    let secondCyclePlanDate=moment(secondCycleDate);
                    let thirdCyclePlanDate=moment(thirdCycleDate);

                        if (cancelledPlanDate.isSameOrBefore(firstCyclePlanDate)) {
                            activePlanEndDate = firstCyclePlanDate;

                        } else if (cancelledPlanDate.isSameOrBefore(secondCyclePlanDate)) {
                            activePlanEndDate = secondCyclePlanDate;
                            
                        } else if (cancelledPlanDate.isSameOrBefore(thirdCyclePlanDate)) { 
                            activePlanEndDate = thirdCyclePlanDate;
                        }  
                }
                else if(interval==="month" && intervalCount==6){
                    firstCycleDate = getDateAftersixMonths(start_Date);
                    const firstCycleEndDate = isoStringToUnixTimeStamp(firstCycleDate)

                    secondCycleDate = getDateAftersixMonths(firstCycleEndDate);
                    const secondCycleEndDate = isoStringToUnixTimeStamp(secondCycleDate)

                    thirdCycleDate = getDateAftersixMonths(secondCycleEndDate);
                    const thirdCycleEndDate = isoStringToUnixTimeStamp(thirdCycleDate)

                    fourCycleDate = getDateAftersixMonths(thirdCycleEndDate);
                    const fourCycleEndDate = isoStringToUnixTimeStamp(fourCycleDate)
                    
                    fiveCycleDate = getDateAftersixMonths(fourCycleEndDate);
                    const fiveCycleEndDate = isoStringToUnixTimeStamp(fiveCycleDate)

                    sixCycleDate = getDateAftersixMonths(fiveCycleEndDate);
                
                    let firstCyclePlanDate=moment(firstCycleDate);
                    let secondCyclePlanDate=moment(secondCycleDate);
                    let thirdCyclePlanDate=moment(thirdCycleDate);
                    let fourCyclePlanDate=moment(fourCycleDate);
                    let fiveCyclePlanDate=moment(fiveCycleDate);
                    let sixCyclePlanDate=moment(sixCycleDate);
                
                        if (cancelledPlanDate.isSameOrBefore(firstCyclePlanDate)) {
                            activePlanEndDate = firstCyclePlanDate;

                        } else if (cancelledPlanDate.isSameOrBefore(secondCyclePlanDate)) { 
                            activePlanEndDate = secondCyclePlanDate;
                            
                        } else if (cancelledPlanDate.isSameOrBefore(thirdCyclePlanDate)) { 
                            activePlanEndDate = thirdCyclePlanDate;
                        }  
                        else if (cancelledPlanDate.isSameOrBefore(fourCyclePlanDate)) {
                            activePlanEndDate = fourCyclePlanDate;
                        }
                        else if (cancelledPlanDate.isSameOrBefore(fiveCyclePlanDate)) {
                            activePlanEndDate = fiveCyclePlanDate;
                        }
                        else if (cancelledPlanDate.isSameOrBefore(sixCyclePlanDate)) { 
                            activePlanEndDate = sixCyclePlanDate;
                        }   
                }
                else if(interval==="year" && intervalCount==1){
                    activePlanEndDate = end_date;
                }
                else if(interval==="day" && intervalCount==1){
                    activePlanEndDate = end_date;
                }


                let is_trial_cancelled,is_plan_cancelled;
                let subscriptionCancelBeforeTrialEnd,subscriptionCancelAfterTrialEnd;
                let subscriptionScheduleCanceled_at = subscriptionSchedule.canceled_at;
                let subcancelledDate = moment.unix(subscriptionScheduleCanceled_at);
                let subcancelledPlanDate=moment(subcancelledDate);
                    
                    if(subcancelledPlanDate.isSameOrBefore(trialEnd) ){

                        subscriptionCancelBeforeTrialEnd= await User.update({_id: userId}, {is_trial_cancel: true,is_trial_running:false});
                        is_trial_cancelled = subscriptionCancelBeforeTrialEnd.is_trial_cancel;

                        is_plan_cancelled = subscriptionCancelBeforeTrialEnd.is_plan_cancel;

                        await Payment.deleteMany({ user_id: userId });

                        current_phase ={
                            //subscribeScheduleId:subscribeScheduleId,
                            //startDate:start_date,
                            //endDate:end_date,
                            //trialEnd:trialEnd,
                            //cancelledDate:subcancelledDate,
                            //activePlanEndDate:activePlanEndDate,
                            is_trial_cancel:is_trial_cancelled,
                        }
                        //return badRequestError(res, messages.invalid_input,current_phase);
                        return okResponse(res, messages.subscription_cancelled,current_phase);

                    }
                    
                    else if(subcancelledPlanDate.isAfter(trialEnd) && trial_End !==null){
                        
                        subscriptionCancelAfterTrialEnd= await User.update({_id: userId}, {is_plan_cancel: true,is_trial_cancel: true});

                         is_plan_cancelled =subscriptionCancelAfterTrialEnd.is_plan_cancel;


                         is_trial_cancelled = subscriptionCancelAfterTrialEnd.is_trial_cancel;
                        
                        current_phase ={
                            subscribeScheduleId:subscribeScheduleId,
                            startDate:start_date,
                            endDate:end_date,
                            trialEnd:trialEnd,
                            cancelledDate:subcancelledDate,
                            activePlanEndDate:activePlanEndDate,
                            //is_trial_cancel:is_trial_cancelled,
                            is_plan_cancel: is_plan_cancelled
                        }
                

                        const currentPhase = {
                            startDate:new Date(current_phase.startDate).toISOString(),
                            endDate:new Date(current_phase.endDate).toISOString(),
                            trialEnd:new Date(current_phase.trialEnd).toISOString(),
                            activePlanEndDate:new Date(current_phase.activePlanEndDate).toISOString(),
                            //is_plan_cancel:current_phase.is_plan_cancel,
                        }

                         await Payment.update({ user_id: userId,is_schedule:true},{current_phase:currentPhase});

                        //return badRequestError(res, messages.invalid_input,current_phase);
                        return okResponse(res, messages.subscription_cancelled,current_phase);


                    }

                    else if(subcancelledPlanDate.isSameOrBefore(end_date) && trial_End ==null){
                        
                        subscriptionCancelAfterTrialEnd= await User.update({_id: userId}, {is_plan_cancel: true});

                         is_plan_cancelled =subscriptionCancelAfterTrialEnd.is_plan_cancel;

                         is_trial_cancelled = subscriptionCancelAfterTrialEnd.is_trial_cancel;

                        current_phase ={
                            subscribeScheduleId:subscribeScheduleId,
                            startDate:start_date,
                            endDate:end_date,
                            cancelledDate:subcancelledDate,
                            activePlanEndDate:activePlanEndDate,
                            is_plan_cancel: is_plan_cancelled
                        }
                

                        const currentPhase = {
                            startDate:new Date(current_phase.startDate).toISOString(),
                            endDate:new Date(current_phase.endDate).toISOString(),
                            activePlanEndDate:new Date(current_phase.activePlanEndDate).toISOString(),
                            //is_plan_cancel:current_phase.is_plan_cancel,
                        }

                         await Payment.update({ user_id: userId,is_schedule:true},{current_phase:currentPhase});

                        //return badRequestError(res, messages.invalid_input,current_phase);
                        return okResponse(res, messages.subscription_cancelled,current_phase);


                    }

                    
                }
    } catch (error) {
        logger.log(level.error, `cancelTrail Error: ${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

export const updateCustomer = async (req, res) => {
    try {
        const { body } = req;
        const {customerId, defaultPaymentMethodId} = body;

        logger.log(level.info, `updateCustomerDetail body=${beautify(body)}`);
        const deletedCondition = { is_deleted: false };

        const filter = { _id: req['currentUserId'] };
        const userId = req['currentUserId'];

        if(!customerId){
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "customerId"));
        }
        
        if(!defaultPaymentMethodId){
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "defaultPaymentMethodId"));
        }
        
        const notExist = await returnOnNotExist(User, { _id: userId, ...deletedCondition }, res, "User", messages.not_exist.replace("{dynamic}", "User"));
        if (notExist) return;
        
        const customerNotExist = await returnOnNotExist(User, { customer_id: customerId, ...deletedCondition }, res, "User", messages.not_exist.replace("{dynamic}", "CustomerId"));
        if (customerNotExist) return;
 
        if(customerId) {
            const updateCustomer = await stripe.customers.update(customerId,{
                invoice_settings: {default_payment_method: defaultPaymentMethodId}
                });

        const payload = {};
        
        if (defaultPaymentMethodId) payload['defaultPaymentMethodId'] = updateCustomer.invoice_settings;

                const customerUpdate = await User.update(filter, payload);

            if(customerUpdate){
                logger.log(level.info, 'Customer Updated Successfully');
                return okResponse(res, messages.updated.replace("{dynamic}", "Customer"), customerUpdate);
            }
        };
    } catch (error) {
        logger.log(level.error, `Stripe Update customer error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};
export const getInvoices = async (req, res) => {
    try {
        const { body } = req;
        const {invoiceId,paymentid} = body;

        logger.log(level.info, `getInvoicesDetail body=${beautify(body)}`);
        const deletedCondition = { is_deleted: false };

        const filter = { _id: req['currentUserId'] };
        const userId = req['currentUserId'];

        // if(!paymentid){
        //     return paramMissingError(res, messages.missing_key.replace("{dynamic}", "paymentid"));
        // }

        if(!invoiceId){
            return paramMissingError(res, messages.missing_key.replace("{dynamic}", "invoiceId"));
        }
        
        // const paymentIdNotExist = await returnOnNotExist(Payment, { _id: paymentid, ...deletedCondition }, res, "paymentid", messages.not_exist.replace("{dynamic}", "paymentid"));
        // if (paymentIdNotExist) return;
        
        // const invoideIdNotExist = await returnOnNotExist(User, { customer_id: customerId, ...deletedCondition }, res, "invoiceId", messages.not_exist.replace("{dynamic}", "invoiceId"));
        // if (invoideIdNotExist) return;

 
        if(invoiceId) {
            const invoice = await stripe.invoices.retrieve(
                invoiceId
              );
              const paymentUrl = invoice.hosted_invoice_url;
              const invoice_pdf = invoice.invoice_pdf;
              const paymentStatus = invoice.status;

              const paymentData ={
                paymentUrl:paymentUrl,
                invoice_pdf:invoice_pdf,
                paymentStatus:paymentStatus,
              }

                logger.log(level.info, 'Get Invoice for Make Paymentment');
                return okResponse(res, messages.created.replace("{dynamic}", "Invoice"), paymentData);
            }
    } catch (error) {
        logger.log(level.error, `Stripe Invoice Get Paymentment Link error${beautify(error.message)}`);
        return internalServerError(res, error)
    }
};

// Function to convert Unix timestamp to formatted date
function formatDate(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toISOString(); // Returns the date in "YYYY-MM-DDTHH:mm:ss.sssZ" format
  }
  // Generate a unique referenceMandateId using UUID v4 with "M" prefix
function referenceMandateId() {
    const uuid = uuidv4(); 
    return `mandate_${uuid}`; 
  }

  function getDateAfterThreeMonths(customTimestamp) {
        customTimestamp = parseInt(customTimestamp, 10);

        const currentDate = moment.unix(customTimestamp);
        currentDate.add(3, 'months');

        const date = currentDate.toDate();
        // Format the resulting date as "YYYY-MM-DD"
    return date.toISOString();
  }
  function getDateAftersixMonths(customTimestamp) {
        customTimestamp = parseInt(customTimestamp, 10);

        const currentDate = moment.unix(customTimestamp);
        currentDate.add(6, 'months');

        const date = currentDate.toDate();
        // Format the resulting date as "YYYY-MM-DD"
    return date.toISOString();
  }

  function isoStringToUnixTimeStamp(isoToUnixTime){
        const date = moment(isoToUnixTime);
            const unixTimestamp = date.unix();
    return unixTimestamp;
  }