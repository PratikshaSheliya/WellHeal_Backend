import { createLogger, format, transports } from 'winston';

const { combine, timestamp, label, printf, colorize } = format;

const LOG_LABEL = 'TM_LOGS';
/* const LOG_TIMEZONE = 'Australia/Melbourne';
const LOCALE = 'en-US'; */
const LOG_TIMEZONE = 'Asia/Kolkata';
const LOCALE = 'en-IN';

const timezoned = () => {
    return new Date().toLocaleString(LOCALE, {
        timeZone: LOG_TIMEZONE,
    });
};

const customFormat = printf(({
    level,
    message,
    label,
    timestamp
}) => {
    return `${timestamp} [${label}] ${level}: ${message}`;
});

const combineFormat = combine(
    label({
        label: LOG_LABEL
    }),
    timestamp({
        format: timezoned
    }),
    colorize(true),
    customFormat
);

const transportsDetails = [];

if (process.env.IS_CONSOLE == 'true') {
    transportsDetails.push(
        new transports.Console({
            level: process.env.LOG_LEVEL,
            format: combineFormat,
            timestamp: function() {
                return new Date().toLocaleTimeString();
            },
        })
    );
} else {
    transportsDetails.push(
        new transports.Console({
            level: process.env.LOG_LEVEL,
            format: combineFormat,
            timestamp: function() {
                return new Date().toLocaleTimeString();
            },
        })
    );
}
var logger = createLogger({
    transports: transportsDetails,
});

export default logger;