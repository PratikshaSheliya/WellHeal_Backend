export const TYPES = Object.freeze({
    LOGIN_TYPE_NORMAL: 0,
    LOGIN_TYPE_GOOGLE: 1,
    LOGIN_TYPE_FACEBOOK: 2,
    LOGIN_TYPE_APPLE: 3
})

export const QUESTION_TYPES = Object.freeze({
    SPLASH_QUESTION: 1,
    REVIEW_QUESTION: 2
})

export const FAVORITE_CONTENT_TYPE = Object.freeze({
    THERAPY: 1,
    1: "Therapy",
    RESOURCE: 2,
    2: "Resource"
})

export const RESOURCE_FORMAT = Object.freeze({
    VIDEO: 1,
    AUDIO: 2
})
export const SLUG_RESOURCE_FORMAT = Object.freeze({
    IMAGE: 1,
    VIDEO: 2
})

export const IMAGE_EXTENSIONS = Object.freeze({
    JPG: '.jpg',
    JPEG: '.jpeg',
    PNG: '.png'
})

export const VIDEO_EXTENSIONS = Object.freeze({
    WEBM: '.webm',
    MPV: '.mpv',
    MPEG: '.mpeg',
    MP4: '.mp4',
    M4V: '.m4v',
    AVI: '.avi',
    WMV: '.wmv',
    MOV: '.mov',

})

export const AUDIO_VIDEO_EXTENSIONS = Object.freeze({
    ...VIDEO_EXTENSIONS,
    M4P: '.m4p',
    MP3: '.mp3',
    AUP: '.aup',
})

export const DOC_EXTENSIONS = Object.freeze({
    doc: '.doc',
    docx: '.docx',
    pdf: '.pdf'
})

export const INTRO_VIDEO_FOR = Object.freeze({
    APP: 0,
    CATEGORY: 1,
    SUBCATEGORY: 2
})

export const DEVICE_TYPE = Object.freeze({
    ANDROID: 'A',
    IOS: 'I'
})

export const GENDER = Object.freeze({
    Male: 'M',
    Female: 'F'
})

export const SLUG_TYPE = Object.freeze({
    SPLASH_SCREEN: 1,
    PRIVACY_POLICY: 2,
    FAQ: 3,
    HELP_FEEDBACK: 4,
    TERMS_CONDITION: 5,
    MORNING_IMAGE: 6,
    EVENING_IMAGE: 7,
    NIGHT_IMAGE: 8,
    APP_ANDROID_VERSION: 9,
    APP_IOS_VERSION: 10,

})

export const COUPON_TYPE = Object.freeze({
    TRIAL_COUPON: 1,
    FREE_COUPON: 2,
    DISCOUNT_COUPON: 3,
    FREE_FOREVER_COUPON: 4,
});

export const COUPON_FOR_WHO = Object.freeze({
    SINGLE_USER: 1,
    ALL_USER: 2
});

export const USER_PRO_STATUS = Object.freeze({
    TRIAL_EXPIRED: 'is_trial_expired',
    TRIAL: 'trial',
    PRO: 'pro',
    FREE_FOREVER: 'free_forever'
})

export const DISCOUNT_TYPE = Object.freeze({
    PERCENT: 1,
    AMOUNT: 2
});

export const REFERRER_TYPE = Object.freeze({
    DOCTOR: 1,
    PATIENT: 2
});

export const USER_ROLE = Object.freeze({
    DOCTOR: 1,
    PATIENT: 2
});

export const MODAL_ID = Object.freeze({
    Category: 'category_id',
    SubCategory: 'subcategory_id',
    Therapy: 'therapy_id',
    SubCategoryTherapy: 'subcategorytherapy_id',
    ResourceType: 'resourcetype_id',
    Resource: 'resource_id',
    TherapyResources: 'therapyresources_id',
    Favorites: 'favorites_id',
    IntroVideos: 'introvideos_id',
    Question: 'question_id',
    ReviewRating: 'reviewrating_id',
    SubCategoryResource: 'subcategoryresource_id',
    SubCategoryType: 'subcategorytype_id',
    User: 'user_id',
    UserAnswers: 'useranswers_id',
    UserProgress: 'userprogress_id',
    UserToken: 'usertoken_id',
    Admin: 'admin_id',
    Slug: 'slug_id',

});

