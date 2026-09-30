// Keyword lists for language analysis
//
// Two tiers per category:
//
//   strong — phrases that are themselves a red flag ("update your bank
//            details", "you have 48 hours to pay"). These drive the score and
//            the verdict floors.
//   broad  — words that only say what a message is about ("invoice", "VAT",
//            "fee", "deadline"). They are always highlighted and listed so the
//            analyst sees every money, pressure and persuasion cue in the mail,
//            but they add nothing to the score: ordinary invoices are full of
//            them, and they must not turn every business email Suspicious.
//
// Matching is whole-word and case-insensitive, runs across line breaks and
// hyphens, and accepts a plural on the last word ("fee" matches "fees").
// To add a term, put it on its own line or after a comma in the right block.
//
// Built from the phrasing seen in real phishing and fraud, cross-checked with
// open sources: Apache SpamAssassin's advance-fee rules (Apache-2.0), published
// phishing and BEC subject-line analyses, government guidance on tax-refund,
// parcel and sextortion scams, and research on Cialdini's persuasion principles
// in phishing mail.
//
// A few very common words (now, today, please, help, call, message, dear) are
// left out on purpose: they would match nearly every email and bury the rest.
// Phrases that contain them ("call this number", "dear beneficiary") are in.

/** Split a block of terms on newlines and commas; blank lines are ignored. */
const list = (block) =>
  [...new Set(block.split(/[\n,]/).map((t) => t.trim().toLowerCase()).filter(Boolean))];

export const CATEGORIES = {
  // ===========================================================================
  urgency: {
    label: "Urgency / Pressure",
    weight: 1.0,
    strong: list(`
      act now, act immediately, act fast, act quickly, act today
      action required, immediate action, immediate action required, urgent action, urgent action required
      requires your immediate attention, requires immediate attention, needs your immediate attention
      your immediate attention, urgent attention, your urgent attention, urgent response, urgent reply
      respond immediately, respond urgently, reply immediately, reply urgently, reply asap, respond asap
      respond within 24 hours, respond within 48 hours, reply within 24 hours
      within 24 hours, within 48 hours, within 72 hours, within 12 hours, within 2 hours, within one hour
      within the next 24 hours, within the next 48 hours, within the next hour, in the next 24 hours
      before midnight, by end of day, by end of business, by close of business, before the end of the day
      before it's too late, before it is too late
      don't delay, do not delay, don't miss out, do not miss out, don't wait, do not ignore, do not ignore this
      failure to respond, failure to comply, failure to act, failure to verify, failure to update, failure to confirm
      if you fail to, if you do not respond, if you don't respond, if no action is taken, if we do not hear from you
      your account will be suspended, your account will be locked, your account will be closed
      your account will be deactivated, your account will be terminated, your account will be disabled
      your account will be deleted, your account will be restricted, your account will be blocked
      your mailbox will be deleted, your mailbox will be suspended, your mailbox will be deactivated
      your email will be deactivated, your email will be suspended, your email account will be closed
      your password will expire, your password expires today, your password has expired
      account will be suspended, account will be locked, account will be closed, account will be deactivated
      access will be revoked, access will be terminated, access will be suspended
      service will be interrupted, service will be terminated, service will be suspended, service will be discontinued
      will be permanently deleted, will be permanently disabled, will be permanently closed, will be lost
      messages will be deleted, pending deletion, scheduled for deletion, scheduled for deactivation
      final warning, final notice, final reminder, final demand, last warning, last notice, last reminder
      last chance, last opportunity, second notice, second reminder, third notice, third reminder
      time sensitive, time is running out, time running out, running out of time
      expires today, expires tomorrow, expires tonight, expires soon, expiring soon, expires in
      will expire, has expired, about to expire, is about to expire, due to expire
      limited time, limited time offer, limited time only, offer expires, offer ends
      only today, today only, one day only, while supplies last, only a few left, only a few hours left
      deadline today, deadline tomorrow, deadline approaching, deadline is approaching
      due today, due immediately, payment due today, due by end of day
      immediately after reading, as soon as possible, as soon as you receive this
      right away, at once, without delay, without further delay
      time critical
      urgent request, urgent matter, urgent task, urgent notice, urgent notification, urgent reminder
      urgent update, urgent security update, urgent message, urgent assistance, urgent business
      verify now, confirm now, update now, login now, log in now, sign in now, click now, respond now
      call now, pay now, renew now, activate now, reactivate now, restore now, unlock now, validate now
      claim now, apply now, download now, open now, review now, act before
      urgent, urgently, immediately, hurry, deadline, expires in, your account expires
    `),
    broad: list(`
      urgency, asap, immediate, promptly, quickly, rush, rushed, expedite, expedited
      deadlines, expire, expires, expired, expiring, expiration, expiry
      overdue, past due, reminder, reminders, final, critical, important, priority, attention
      required, requirement, pending, awaiting, outstanding, suspended, suspension, suspend
      interrupted, interruption, locked, lockout, lock, deactivate, deactivated, deactivation
      terminate, terminated, termination, restricted, restriction, restrict, limited, limitation
      disabled, disable, blocked, block, frozen, freeze, closure, closing, cancelled, canceled, cancellation
      tonight, midnight, eod, cob, end of day, close of business, 24 hours, 48 hours, 72 hours
      warning, last, soon, quick, fast, instant, instantly, now or never
      // Common in ordinary mail: shown, never decisive.
      as soon as you can, at your earliest convenience, no later than, high priority, top priority
      priority action, highest priority
    `),
  },

  // ===========================================================================
  authority: {
    label: "Authority / Fear / Threat",
    weight: 1.2,
    strong: list(`
      legal action, legal proceedings, legal consequences, take legal action, further legal action
      court order, court summons, arrest warrant, warrant for your arrest
      you will be arrested, arrest will be made, law enforcement, federal agent, cease and desist
      internal revenue service, tax authority, tax authorities, tax office, revenue service, revenue agency
      department of justice, homeland security, social security administration, social security number
      ministry of interior, ministry of finance, federal bureau, border force, customs and border
      security breach, data breach, breach of security, unauthorized access, unauthorised access
      unauthorized login, unauthorised login, unauthorized transaction, unauthorised transaction
      unusual activity, unusual sign-in activity, unusual sign in activity, unusual login attempt, unusual login
      suspicious activity, suspicious login, suspicious sign-in, suspicious sign in, suspicious transaction
      fraudulent activity, fraudulent transaction, fraudulent charge
      your account has been compromised, your account was compromised, your account has been hacked
      your account was accessed, your account has been accessed, someone tried to access your account
      someone has access to your account, someone logged into your account, new sign-in detected
      we detected, we have detected, we noticed, we have noticed, we have identified, we identified
      violation of our terms, violated our terms, terms of service violation, policy violation, violation of policy
      copyright infringement, dmca notice, trademark infringement, penalty charge, penalty notice
      fine will be imposed, you will be fined, you will be charged, you will be penalized, you will be penalised
      compliance required, compliance violation, non-compliance, non compliance, audit notice
      under investigation, criminal investigation, criminal charges, criminal record
      your account has been flagged, you have been reported, reported for, flagged for, blacklisted
      official notice, official notification, official warning, formal notice, legal notice
      notice of termination, notice of suspension, notice of violation, notice of intent
      your account has been compromised, your account has been suspended, your account has been locked
      your account has been limited, your account has been restricted, your account has been disabled
      account has been suspended, account has been locked, account has been limited, account has been restricted
      security alert, security notice, security warning, security notification, security incident
      email administrator, mail administrator
      webmaster, postmaster, microsoft security team, account security team
      irs, hmrc, fbi, interpol, cia, europol, cyber crime unit, cybercrime unit
      court, attorney, lawsuit, government, federal, mandatory, obligatory, penalty, violation
      official notice, your account has been compromised, final notice
    `),
    broad: list(`
      legal, lawyer, solicitor, barrister, counsel, sue, sued, suing, prosecution, prosecute
      litigation, tribunal, judge, judgment, judgement, verdict, summons, subpoena, warrant, arrest, arrested
      police, officer, agent, agency, authority, authorities, official, officials, governmental
      ministry, embassy, consulate, department, state, municipal, council, commission, regulator
      regulation, regulatory, regulations, compliance, comply, audit, auditor, auditing, inspection
      investigation, investigate, investigator, violations, violated, breach, breached
      penalties, fine, fined, sanction, sanctions, sanctioned, seized, seizure, confiscated
      compromised, hacked, hack, unauthorized, unauthorised, suspicious, fraudulent, fraud, scam
      illegal, unlawful, criminal, crime, offence, offense, infringement, liability, liable, prosecution
      consequences, consequence, threat, threaten, threatened, enforcement, enforce, enforced
      warning, alert, notice, notification, security, secure, protection, protect, risk, danger, dangerous
      administrator, admin, moderator, supervisor, headquarters, executive, chairman, chairwoman
      president, vice president, director, managing director, ceo, cfo, coo, cto, cio, ciso, founder
      board of directors, management, it team, security team, support team, customer service
      human resources, hr department, payroll department, finance department, accounts department
      cra, ato, dhs, doj, ssa, fca, sec, finra
      microsoft, apple, google, amazon, paypal, netflix, dhl, fedex, ups, usps, royal mail
      // Common in ordinary mail: shown, never decisive.
      court date, court hearing, it department, it support, it helpdesk, it help desk, it service desk
      help desk, helpdesk, system administrator, network administrator, mail delivery subsystem, compliance department
      legal department, fraud department, fraud prevention team, risk department, police department
    `),
  },

  // ===========================================================================
  financial: {
    label: "Money / Financial",
    weight: 1.1,
    strong: list(`
      wire transfer, bank transfer, telegraphic transfer, money transfer, fund transfer, funds transfer
      transfer of funds, electronic funds transfer, ach transfer, ach payment, swift transfer, sepa transfer
      iban number, routing number, aba number, bank account number
      sort code, bank details, banking details, bank information, banking information, bank account details
      account details, payment details, payment information, billing information, billing details
      card details, credit card details, credit card number, debit card number, card number
      card verification value, cvv, cvv2, cvc, pin number, card pin, atm pin
      update your payment information, update your billing information, update your payment details
      update payment method, update your payment method, update your card, update your credit card
      payment method expired, payment declined, payment failed, payment was declined, payment was unsuccessful
      payment could not be processed, unable to process your payment, we could not process your payment
      card declined, your card was declined, card has expired, your card has expired, credit card expired
      outstanding balance, outstanding payment, outstanding amount
      payment overdue, overdue payment
      transfer fee, release fee, clearance fee
      clearing fee, customs fee, customs duty, customs charge, import duty
      redelivery fee, re-delivery fee, activation fee, registration fee
      tax fee, unlock fee
      value added tax, withholding tax, tax refund, tax rebate
      refund request, refund pending, refund approved, refund processed, refund issued, eligible for a refund
      you are eligible for a refund, you are due a refund, reimbursement, compensation payment
      invoice payment, payment request, request for payment, payment confirmation
      payment advice, remittance advice, proof of payment, order confirmation
      transaction confirmation
      gift card, itunes gift card, google play card, google play gift card, amazon gift card, steam card
      steam gift card, apple gift card, ebay gift card, visa gift card, prepaid card, voucher code
      cryptocurrency, crypto wallet, bitcoin, btc, ethereum, usdt, tether, wallet address, bitcoin address
      bitcoin wallet, crypto address, crypto payment, pay in bitcoin, pay in crypto
      investment opportunity, return on investment, guaranteed return, guaranteed profit, double your money
      trading account, forex trading, binary options, crypto trading
      loan approved, pre-approved loan, loan offer, instant loan, debt relief, debt consolidation
      western union, moneygram, ria money transfer, remitly, worldremit, xoom
      bank draft, cashier's check, cashiers check, certified check, money order
      upfront payment, upfront fee, advance fee
      unauthorized charge, unrecognized charge, unrecognised charge, billing error, overcharged, double charged
      chargeback, dispute the charge
      wire transfer, bank transfer, swift, iban, gift card, cryptocurrency, bitcoin, btc, wallet address
      invoice payment, payment request, outstanding payment, banking details, account details
      routing number, update your payment information, payment method expired, credit card expired
      billing information, refund, reimbursement, compensation, transaction, payment confirmation
      order confirmation, amazon gift card, itunes gift card
    `),
    broad: list(`
      money, cash, funds, fund, funding, payment, pay, paid, paying, payable, payee, payer, payout
      invoice, invoiced, invoicing, bill, billing, billed, receipt, statement, balance, amount, sum, total
      price, pricing, cost, costs, fee, charge, charged, charges, tax, taxes, taxation, taxable
      vat, gst, hst, pst, duty, duties, tariff, levy, excise, customs, stamp duty
      bank, banking, banker, account, accounts, bic, routing, aba
      ach, sepa, eft, chaps, bacs, faster payments, wire, wired, wiring, transfer, transferred, transferring
      deposit, deposited, withdraw, withdrawal, withdrawn, remit, remitted, remittance
      disburse, disbursement, disbursed, refunded, rebate, reimburse, reimbursed
      compensate, credit, credited, debit, debited, overdraft, overdrawn
      card, credit card, debit card, prepaid, visa, mastercard, maestro, amex, american express, discover
      pin, atm, pos, merchant, loan, loans, lend, lender, lending, borrow, borrowed, borrower
      debt, debts, owe, owed, owing, due, arrears, collection, collections, collector, creditor, debtor
      installment, instalment, mortgage, interest, interest rate, apr, principal, repayment, repay
      dividend, profit, profits, earnings, income, revenue, salary, salaries, wage, wages, payroll
      paycheck, paycheque, payslip, pay stub, bonus, commission, pension, retirement, annuity, 401k
      invest, investing, investment, investor, portfolio, trading, trader, trade, stock, stocks, shares
      bond, bonds, forex, crypto, eth, litecoin
      dogecoin, solana, xrp, bnb, wallet, coinbase, binance, kraken, blockchain, nft, token, tokens, mining
      currency, exchange rate, dollar, dollars, usd, euro, euros, eur, pound, pounds, gbp, sterling
      dirham, dirhams, aed, riyal, riyals, sar, dinar, rupee, rupees, inr, yen, jpy, yuan, rmb, cny
      franc, chf, naira, rand, cad, aud, cents, million, millions, billion, billions
      purchase, purchased, order, orders, ordered, buy, bought, sell, sold, sale, sales, discount
      voucher, coupon, cheque, checks, escrow, insurance, premium, claim, claims, grant
      subsidy, stimulus, allowance, stipend, wealth, fortune, finance, financial, fiscal, budget
      expense, expenses, reimbursable, treasury, treasurer, accountant, accounting, bookkeeping
      cashier, teller, vendor, supplier, beneficiary, remitter, paypal, venmo, zelle, cash app, cashapp
      stripe, square, wise, transferwise, revolut, payoneer, skrill, neteller, alipay, wechat pay
      apple pay, google pay, subscription, renewal, membership, charity, donation
      // Common in ordinary mail: shown, never decisive.
      swift code, bic code, account number, security code, amount due, balance due, total due, payment due
      late payment, late fee, late payment fee, processing fee, handling fee, service fee, transaction fee
      delivery fee, shipping fee, admin fee, administration fee, administrative fee, legal fee, insurance fee
      conversion fee, income tax, tax return, tax credit, payment receipt, purchase order, transaction id
      transaction reference, transaction number, trading platform, credit score, direct debit, standing order
      down payment, advance payment, prepayment, subscription renewal, auto-renewal, automatic renewal
      renewal fee, membership fee, bank statement, account statement, account balance
    `),
    // Money written as money: amounts, account numbers and wallet addresses.
    patterns: [
      { tier: "broad", re: /[$€£¥₹₽₩₺₦₱]\s?\d[\d,.]*(?:\s?(?:k|m|million|billion))?/g },
      { tier: "broad", re: /\b\d[\d,.]*\s?(?:usd|eur|gbp|aed|sar|inr|cad|aud|chf|jpy|cny|ngn|btc|eth|usdt)\b/gi },
      { tier: "strong", re: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b/g }, // IBAN
      { tier: "strong", re: /\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g }, // Bitcoin address
      { tier: "strong", re: /\b0x[a-fA-F0-9]{40}\b/g }, // Ethereum-style address
    ],
  },

  // ===========================================================================
  credential: {
    label: "Credential Harvesting",
    weight: 1.3,
    strong: list(`
      click here to verify, click here to confirm, click here to update, click here to login
      click here to log in, click here to sign in, click here to restore, click here to unlock
      click here to reactivate, click here to validate, click here to review, click here to view
      verify your account, verify your identity, verify your email, verify your email address
      verify your mailbox, verify your information, verify your details, verify your login
      validate your account, validate your email, validate your mailbox, validate your identity
      confirm your account, confirm your identity, confirm your password, confirm your email
      confirm your details, confirm your information, confirm login details, confirm your login
      update your account, update your details, update your information, update account information
      update your password, reset your password
      re-enter your password, enter your password, provide your password, type your password
      your password has expired, password expiration, password will expire, password expires
      keep your password, keep same password, keep your current password, retain your password
      login to secure, login to verify, log in to verify, sign in to verify, sign in to continue
      log in to continue, login to continue, sign in to view, log in to view, login to view
      sign in to access, log in to access, login to access, sign in to your account, log in to your account
      click the link below, click the button below, click on the link, click on the button below
      follow the link, use the link below, tap the link, open the link
      open the attached, open the attachment, view the attached, view attachment, view document
      view shared document, access document, access the document, review document, review the document
      shared a document with you, shared a file with you, has shared a file, has shared a document
      sent you a document, sent you a file, document has been shared, file has been shared
      secure document, secure message, encrypted message, you have a new secure message
      you have received a secure message, view secure message, read secure message
      you have a new voicemail
      you have received a fax
      mailbox full, mailbox is full, mailbox quota, storage quota, storage full, quota exceeded
      exceeded your quota, exceeded the storage limit, email quota, upgrade your mailbox, increase your mailbox
      pending messages, messages on hold, undelivered messages, incoming messages have been held
      messages have been blocked, release your messages, release pending messages
      message delivery failed, email delivery failure
      account verification, account validation, identity verification, security check, security verification
      reactivate your account, restore your account, unlock your account, restore access, regain access
      recover your account, account recovery, secure your account, secure your account now
      protect your account, keep your account active, avoid suspension, avoid account closure
      avoid losing access, prevent suspension, prevent account closure
      login credentials, login details, log in details, sign-in details, username and password
      user id and password, account credentials, verify credentials, authenticate your account
      mail server upgrade, email upgrade
      accept the new terms
    `),
    broad: list(`
      password, passwords, passcode, pin, login, log in, logon, log on, sign in, sign-in, signin, sign on
      username, user name, user id, userid, credentials, credential, verify, verified, verification
      confirm, confirmed, confirmation, validate, validated, validation, authenticate, authenticated
      authentication, account, accounts, mailbox, inbox, email address, portal, dashboard, profile
      secure, security, update, updated, upgrade, upgraded, reactivate, reactivation, restore, restored
      unlock, unlocked, recover, recovery, reset, click, click here, link, attachment, attachments
      attached, document, documents, file, files, shared, share, download, downloaded, access
      voicemail, fax, scan, scanned, signature, sign, esign, quota, storage, migration, maintenance
      microsoft, outlook, office, onedrive, sharepoint, teams, google, gmail, yahoo, icloud, apple id
      adobe, docusign, dropbox, zoom, webex, slack, linkedin, facebook, instagram, whatsapp
      // Common in ordinary mail: shown, never decisive.
      change your password, password reset, new voicemail, voicemail message, voice message received
      missed call, fax received, new fax, efax, scanned document, scanned file, scan to email, review and sign
      sign the document, please sign, e-signature, electronic signature, adobe sign, google drive
      google docs, wetransfer, box.com, delivery failure, undeliverable, verification code, one-time code
      one time code, one-time password, one time password, otp, authentication code, security code
      two-factor, two factor, 2fa, mfa, multi-factor, multi factor, office 365, microsoft 365, outlook web access
      owa, webmail, email account, mail account, server upgrade, system upgrade, account upgrade, scheduled maintenance
      account migration, email migration, mailbox migration, policy update, terms update, updated terms of service
    `),
  },

  // ===========================================================================
  bec: {
    label: "BEC / Payment Fraud",
    weight: 1.4,
    strong: list(`
      new bank details, updated bank details, change of bank details, change in bank details
      bank details have changed, bank details has changed, our bank account has changed, changed our bank
      new bank account, new account details, updated account details, change of payment details
      updated payment details, new payment details, new remittance details, update the beneficiary
      new beneficiary, beneficiary details, beneficiary account, wire instructions, wiring instructions
      payment instructions, ach transfer, update my direct deposit
      change my direct deposit, payroll change, payroll update, overdue invoice, past due invoice
      unpaid invoice, outstanding invoice, overdue payment, process the payment, process this payment
      release the payment, settle the invoice, proof of payment
      same day payment, same-day payment, transfer the funds, wire the funds
      urgent wire, urgent payment, are you available, are you at your desk
      are you in the office, quick favor, quick favour, quick task, i need a favor, i need a favour
      can you handle a task, keep this confidential, keep this between us, strictly confidential
      confidential transaction, confidential matter, sensitive transaction, do not discuss this
      don't discuss this, don't mention this, i'm in a meeting, i am in a meeting, can't talk right now
      cannot talk right now, reply by email only, send me your cell, send me your mobile number
      purchase gift cards, buy gift cards, scratch the back, send me the codes, send the codes
      change of banking details, change in banking details, update our banking details, new banking details
      new bank information, updated banking information, our new account, use the new account
      do not use the old account, old account is closed, old account has been closed, account is under audit
      our account is under review, account currently under audit, payment should be made to
      please remit to, remit payment to, send payment to, pay to the following account, following account details
      wiring details, wire details, banking instructions, remittance instructions, updated remittance
      vendor bank change, supplier bank details, change of supplier details
      kindly process, kindly make payment, kindly arrange payment, kindly confirm payment
      kindly effect payment, effect the payment, make the payment today, do the needful
      send me your number, whatsapp me, reply on whatsapp
      keep it confidential, don't tell anyone
      surprise for the staff, gift for the staff, appreciation gifts, employee appreciation, staff appreciation
      buy some gift cards, how many can you get, scratch off, scratch them, send pictures of the cards
      take a picture of the cards, pictures of the cards, update my payroll, update my banking information
      change my bank account, new direct deposit
      confidential acquisition
    `),
    broad: list(`
      invoice, invoices, payment, payments, vendor, vendors, supplier, suppliers, remittance
      beneficiary, wire, wiring, payroll, paycheck, deposit, kindly, favour, favor, confidential
      discreet, discretion, available, busy, meeting, travelling, traveling, flight, conference
      gift cards, itunes, steam, google play, apple card, codes, scratch, cfo, ceo, controller
      accounts payable, accounts receivable, ap department, ar department, procurement, purchasing
      // Common in ordinary mail: shown, never decisive.
      sort code, direct deposit, remittance advice, pro forma invoice, proforma invoice, vendor payment
      outstanding invoices, invoices due, invoice due, payment status, confirm payment, when will payment be made
      has payment been made, i need you to, i need your help, can you help me with, are you free, are you around
      let me know when you are free, let me know when you are available, text me, i'm travelling, i am travelling
      i'm traveling, i am traveling, i'm on a flight, i am boarding, in a board meeting, in a conference call
      between us, before the next payroll, next pay date, my paycheck, acquisition, merger, due diligence
      project fund, pre-payment for
    `),
    // The same ideas written in a way no fixed phrase would catch: the
    // instruction, the bank-detail block, the excuse for not talking and the
    // demand for secrecy.
    patterns: [
      { tier: "strong", re: /\b(?:process|approve|release|initiate|arrange|complete|action)\s+(?:a|the|this)?\s*(?:urgent\s+|same[-\s]day\s+)?(?:bank\s+|wire\s+)?(?:transfer|payment|remittance|invoice)\b/gi },
      { tier: "strong", re: /\bwire\s+(?:the\s+)?(?:funds|money|amount|total|\$[\d,.]+)\b/gi },
      { tier: "strong", re: /\btransfer\s+(?:the\s+)?(?:funds|money|amount|\$[\d,.]+)\b/gi },
      { tier: "strong", re: /\b(?:i\s*am|i'm)\s+(?:currently\s+)?(?:in|on)\s+(?:a\s+)?(?:meeting|call|conference)\b/gi },
      { tier: "strong", re: /\b(?:cannot|can't|can\s+not|won't|will\s+not|unable\s+to)\s+(?:be\s+reached|be\s+contacted|talk|speak|discuss|call)\b/gi },
      { tier: "strong", re: /\b(?:i\s+will\s+be|i'll\s+be|i\s+am)\s+unreachable\b/gi },
      { tier: "strong", re: /\b(?:account|routing|swift|iban|sort\s*code|bic)\s*(?:number|code|no\.?)?\s*[:#](?=\s*[A-Z0-9])/gi },
      { tier: "strong", re: /\bdo\s+not\s+(?:delay|discuss|tell|mention|share|inform)\b/gi },
      { tier: "strong", re: /\bjust\s+handle\s+it\b/gi },
      { tier: "strong", re: /\bsend\s+me\s+the\s+(?:confirmation|receipt|proof)\b/gi },
    ],
  },

  // ===========================================================================
  lure: {
    label: "Lure / Reward / Seduction",
    weight: 1.1,
    strong: list(`
      you have won, you've won, you won, you are a winner, you're a winner, you are the winner
      congratulations you have won, congratulations you won, winning notification, award notification
      prize notification, winning ticket, claim your prize, claim your reward, claim your money
      claim your funds, claim your gift, claim your winnings, claim your bonus, claim your refund
      claim your package, your prize, your reward, your winnings, cash prize, grand prize, cash reward
      lottery winner, lottery award, lottery prize, lottery program, jackpot winner, sweepstakes winner
      selected as a winner, randomly selected, you have been selected, you have been chosen, you were selected
      lucky winner, lucky draw, lucky number, free gift, free gift card, free iphone, free money, free cash
      easy money, fast cash, quick cash, extra cash, get rich, get rich quick, earn money from home
      work from home, make money online, make money fast, earn extra income, double your income
      passive income, financial freedom, risk-free, risk free, no risk, 100% free, 100% guaranteed
      guaranteed income, guaranteed returns, no strings attached, no catch
      once in a lifetime, once-in-a-lifetime
      exclusive deal, secret deal, cash bonus, welcome bonus, sign-up bonus, signup bonus
      points expire, your points will expire
      unclaimed funds, unclaimed prize, unclaimed package, unclaimed reward, unclaimed refund
      relief fund, grant approved, you have qualified
      pre-approved, pre approved, you have been approved, instant approval
      easy job, hiring immediately
      no experience needed, no experience required, mystery shopper, secret shopper, personal assistant job
      package waiting, parcel waiting, delivery attempt
      delivery attempt failed, missed delivery, we tried to deliver, we attempted to deliver
      schedule redelivery, reschedule delivery, parcel on hold, package on hold, held at customs
      i saw your profile, i found your profile, i came across your profile, looking for a serious relationship
      looking for love, my love, dear love, beautiful woman, handsome man
      date with me, chat with me, private photos, see my photos, my photos
      hot singles, singles in your area, adult dating, hookup, nude photos, naked photos
      trading bot, crypto opportunity, investment platform, high returns, double your bitcoin
      act now and get, don't miss this offer
    `),
    broad: list(`
      free, win, winner, winners, won, winning, prize, prizes, reward, rewards, gift, gifts, bonus, bonuses
      jackpot, lottery, lotto, sweepstake, sweepstakes, raffle, draw, lucky, congratulations, congrats
      selected, chosen, eligible, eligibility, qualify, qualified, exclusive, special, offer, offers
      deal, deals, discount, cheap, bargain, save, savings, promotion, promo, coupon, voucher, clearance
      cash, rich, wealthy, fortune, millionaire, guarantee, guaranteed, amazing, incredible, unbelievable
      miracle, secret, opportunity, opportunities, profit, earn, earnings, income, job, jobs, hiring
      vacancy, vacancies, recruitment, recruiter, interview, position, salary, love, darling, sweetheart
      honey, beautiful, gorgeous, lonely, single, dating, romance, romantic, flirt, kiss, sexy, adult
      photos, pictures, video, private, parcel, package, shipment, delivery, courier, tracking number
      claim, redeem, unclaimed, approved, approval, trial, subscription
      // Common in ordinary mail: shown, never decisive.
      no obligation, no cost, exclusive offer, special offer, special promotion, limited offer, reward points
      loyalty reward, loyalty points, redeem your, you qualify, you qualify for, you are eligible
      approved for, job offer, work opportunity, part-time job, part time job, remote job, your package
      your parcel, your shipment, my dear, i love you, i miss you, meet you, meet me, free trial, try it free
    `),
  },

  // ===========================================================================
  advancefee: {
    label: "Advance-Fee / 419 Scam",
    weight: 1.3,
    strong: list(`
      next of kin, late husband, late father, late mother, late client, deceased client, deceased customer
      died intestate, left behind, estate of the late, wife of the late, son of the late, daughter of the late
      sole beneficiary, heir to, transfer this fund, transfer the fund, the total sum of
      million united states dollars, million us dollars, million dollars, million euros, million pounds
      consignment, diplomatic courier, diplomatic agent, diplomatic bag, trunk box
      atm card, atm master card, atm visa card, certified bank draft, compensation fund, united nations compensation
      un compensation, imf compensation, world bank compensation, federal ministry of finance
      central bank of nigeria, bank of nigeria, ecowas, foreign partner, foreign business partner
      lucrative business
      percent of the total, % of the total, share of the fund, your share, commission of, sharing ratio
      fiduciary, fiduciary agent, affidavit, affidavit of claim
      certificate of deposit, clearance certificate, anti-terrorism certificate, anti terrorism certificate
      anti-money laundering certificate, drug free certificate, ownership certificate, release order
      approval order, courier charges, delivery charges, security keeping fees, keeping fees, demurrage
      can i trust you, can i completely trust you, can i rely on you, trustworthy person, honest person
      god fearing, god-fearing, i got your contact
      i got your email, your email was selected, your email address won, your email address has won
      reply to my private email, contact me on my private email, private email address, alternative email
      alternate email
      international passport, reconfirm the following
      forward the following information, send the following information, dear friend, dear beneficiary
      dear sir/madam, dear sir or madam, dear sir madam, greetings in the name of
      confidential business, 100% risk free, no risk involved
      legitimate transaction, legal and risk free, over-invoiced, over invoiced, contract payment
      unclaimed fund, dormant account, abandoned fund, abandoned consignment, abandoned box
      terminal illness, cancer patient, orphanage, motherless babies
      oil and gas contract, gold dust, gold bars
      your humble assistance
      your urgent reply, earliest reply, honest cooperation
    `),
    broad: list(`
      kin, estate, deceased, widow, widower, heir, heiress, inheritance, inherit, inherited, beneficiary
      prince, princess, king, queen, colonel, general, soldier, sergeant, captain, diplomat, diplomatic
      barrister, courier, compensation, charity, orphan, orphans, donate, donation, donations
      humanitarian, confidential, trust, honest, honesty, blessings, blessed, oil, gold, diamond, diamonds
      contract, proposal, partner, partnership, investor, fund, funds, transfer, abroad, overseas, foreign
      nigeria, ghana, benin, togo, ivory coast, senegal, cameroon, sierra leone, liberia, burkina faso
      // Common in ordinary mail: shown, never decisive.
      the sum of, security company, business proposal, mutually beneficial, business relationship with you
      attorney at law, legal representative, i am contacting you, i am writing to you, your full name
      your home address, your phone number, your age and occupation, copy of your id, copy of your passport
      yours faithfully, god bless you, remain blessed, charity work, crude oil, bank of england, reserve bank
      united nations, world bank, imf, federal government, immediate response
    `),
  },

  // ===========================================================================
  social: {
    label: "Social Engineering",
    weight: 1.0,
    strong: list(`
      do not share this email, do not forward this email, don't tell anyone, don't let anyone know
      keep this to yourself, just between us, for your eyes only, can you do me a favor, can you do me a favour
      i left you a voicemail, i tried calling you, i tried to call you, call me back, call us at
      call this number, call our support, call our billing department, call immediately
      call us immediately, call the number below
      if you did not make this purchase, if you did not authorize, if you did not authorise
      if this wasn't you, if this was not you, if you did not request, if you don't recognize
      if you do not recognize, if you do not recognise, was this you, did you sign in, did you request
      cancel this order, cancel the transaction, to cancel this, dispute this charge, to dispute
      antivirus renewal
      your computer is infected, virus detected, your device has been infected, your system is compromised
      your device is at risk, install this, download this
      enable content, enable editing, enable macros, open in desktop app, open in desktop
      is this you, is this you in the video, i found this photo
      you have been tagged, someone mentioned you
      your manager asked, the ceo asked
      gift for completing, dear customer, dear user, dear client, dear member, dear account holder
      dear valued customer, dear valued member, dear email user, dear mailbox user, dear employee
      dear staff, dear colleague, hello dear, greetings dear
      as a valued customer, your colleagues have already
      everyone in the team has
      i trust you, you can trust, i count on you, i rely on you
      i need your assistance, your assistance is needed, i would appreciate your help
      reply to this number, contact me on
    `),
    broad: list(`
      confidential, private, privately, secret, secretly, trust, trusted, trusting, favor, favour, favors
      assist, assistance, kindly, appreciate, grateful, cooperation, cooperate, discreet, discretion
      personal, personally, curious, surprise, exclusive, quietly, callback, voicemail, notification
      survey, feedback, colleague, colleagues, team, manager, boss, supervisor, staff, employee, employees
      policy, handbook, benefits, enrollment, enrolment, review, reviewed, request, requested, requesting
      follow up, following up, checking in, quick question, reminder, recall, remember
      whatsapp, telegram, signal, wechat, viber, skype, sms, text, texting, phone number, mobile number
      cell number, extension, hotline, support line, helpline, customer care, support
      // Common in ordinary mail: shown, never decisive.
      as discussed, as per our conversation, as per our discussion, following our phone call, following our conversation
      per our call, further to our conversation, as we discussed, contact us at, toll-free, toll free
      customer support number, your order has been shipped, your subscription has been renewed, your subscription will renew
      geek squad, norton, mcafee, tech support, technical support team, remote access, teamviewer
      anydesk, see attached, see attachment, find attached, please find attached, please review the attached
      attached file, attached document, open the document, check the attached, invoice attached, look at this
      check this out, new message from, you have a new message, you have unread messages, unread message
      personal message, private message, your colleague, on behalf of, reaching out on behalf of, authorized by
      approved by management, per management, as requested by, requested by, company policy, new company policy
      hr policy, handbook update, employee handbook, benefits enrollment, open enrollment, salary increase
      salary adjustment, pay rise, pay increase, bonus announcement, performance review, termination notice
      layoff, layoffs, list of employees, employee list, health update, covid-19, vaccine, feedback survey
      complete the survey, take the survey, valued customer, valued member, we value your privacy
      we appreciate your loyalty, join thousands, trusted by millions, as seen on, recommended by
      trust me, believe me, i promise, signal app, text message, reply to this email, reply with your
      send us your, provide the following, fill out the form, fill in the form, complete the form
      attached form, update form
    `),
    // A callback-phishing tell: a phone number offered as the way to "fix" it.
    patterns: [
      { tier: "strong", re: /\b(?:call|contact|dial|phone|reach)\b[^.\n]{0,40}?\+?\d[\d\s().-]{7,}\d/gi },
    ],
  },

  // ===========================================================================
  extortion: {
    label: "Extortion / Sextortion",
    weight: 1.5,
    strong: list(`
      i have access to your device, i have access to your computer, i have access to your phone
      i have full access, i hacked your, i have hacked, your device was hacked, your device has been hacked
      i installed a trojan, i installed malware, i installed a virus, i installed spyware
      remote access trojan, i recorded you, i have recorded, recorded a video
      recorded video of you, i have a video, video of you, videos of you, your webcam, through your webcam
      your camera was on, while you were watching
      masturbating, intimate video, intimate photos, compromising video
      compromising material, compromising photos, embarrassing video, embarrassing photos
      all your contacts, send it to your contacts, send to your friends and family
      share it with your contacts
      i will leak, i will expose
      expose you, ruin your reputation, your life will be ruined
      your password is, i know your password, i know your secret, i know what you did
      transfer to my bitcoin, my bitcoin address, my btc address, my wallet address
      pay in bitcoin, payment in bitcoin, amount in bitcoin
      you have 48 hours, you have 24 hours, you have 72 hours, 48 hours to pay, 24 hours to pay
      i will delete the video, i will delete everything, delete the evidence, delete the recording
      once i receive the payment, after receiving payment, as soon as the payment is received
      do not try to contact the police, don't go to the police, if you contact the police, contacting the police
      i will know if you read this, i will know when you open this
      it is useless to reply
      your files have been encrypted, decrypt your files, we have your data
      we will publish your data, we will leak your data
      pay the ransom, send the ransom
    `),
    broad: list(`
      bitcoin, btc, crypto, wallet, webcam, camera, video, recording, recorded, record, porn, adult
      hacked, hacker, hackers, malware, trojan, virus, spyware, keylogger, leak, leaked, leaking
      expose, exposed, exposure, reputation, blackmail, ransom, extortion, extort, threat, threats
      shame, shameful, humiliate, humiliation, embarrassing, embarrassment, secret, secrets, evidence
      contacts, friends and family, relatives, police, deleted, delete, destroy, encrypted, decrypt
      // Common in ordinary mail: shown, never decisive.
      rat software, adult websites, adult website, adult content, pornography, pornographic, your contacts
      your friends and colleagues, your family and friends, i will send, i will publish, i will release
      i will share, your reputation will be ruined, i know everything, pay me, bitcoin wallet, btc wallet
      btc address, pixel tracking, tracking pixel, this is not a joke, not a threat, nothing personal
      your data has been stolen, data will be published, ransomware
    `),
  },
};

/**
 * Weight of a broad-term match relative to a strong one. Zero: broad words are
 * for the analyst's awareness only, and never move the score or the verdict.
 */
export const BROAD_WEIGHT = 0;
