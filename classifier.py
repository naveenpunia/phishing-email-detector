import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# Labeled dataset of common email texts (0 = Legitimate/Safe, 1 = Phishing)
TRAINING_DATA = [
    # Phishing Examples
    ("Dear customer, your bank account has been locked. Verify identity immediately at link.", 1),
    ("Immediate action required: Netflix membership suspended due to payment details issue.", 1),
    ("You have won a free gift card of $500! Click here to claim your reward now.", 1),
    ("Please verify your PayPal credentials using the secure portal link below.", 1),
    ("Your password for Chase Online banking will expire in 24 hours. Reset it now.", 1),
    ("Unauthorized login attempt detected on your account. Confirm your identity to unlock.", 1),
    ("Urgent: your billing details are incorrect. Update your subscription payment now.", 1),
    ("Document shared with you on Google Drive. Click here to sign in and view invoice.", 1),
    ("Warning! Your social security number SSN was flagged. Contact support immediately.", 1),
    ("IRS refund notification: claim your tax return payment of $1200 via secure link.", 1),
    ("Verify your Apple ID info to prevent termination of iCloud storage services.", 1),
    ("Urgent invoice payment is overdue. Download the attachment and review billing details.", 1),
    ("Your Wells Fargo card is deactivated. Click the link to update secure pin.", 1),
    ("Suspicious activity detected on your bank login. Reactivate your access code immediately.", 1),
    ("Get a free bonus today. Click this hyperlink to start earning cash online.", 1),
    ("Dear user, update your Microsoft Outlook email inbox account credentials.", 1),
    ("Your invoice #83921 is past due. Please review the attached document now.", 1),
    ("Update your shipping information to receive your Amazon package delivery.", 1),
    
    # Safe/Legitimate Examples
    ("Hi team, here is the agenda for our weekly sync meeting on Monday morning.", 0),
    ("Hey, are we still on for lunch today at the cafe? Let me know.", 0),
    ("Your receipt for purchase at Starbucks. Thank you for your order.", 0),
    ("Welcome to our newsletter! Here are the top design articles of the week.", 0),
    ("Your weekly report is ready. Please find the PDF breakdown attached.", 0),
    ("Thanks for registering for the webinar. The Zoom link is included below.", 0),
    ("Hi Naveen, could you review the code updates on github pull request?", 0),
    ("Project status update: we successfully deployed the staging environment.", 0),
    ("Happy birthday! Wishing you a great day ahead and a fantastic year.", 0),
    ("Meeting request: discussing marketing budgets for the next quarter.", 0),
    ("Your package has been shipped and is scheduled for delivery tomorrow.", 0),
    ("Thanks for applying. We reviewed your profile and want to schedule an interview.", 0),
    ("Hey mom, I will visit you this weekend. Let me know if you need anything.", 0),
    ("Your subscription has renewed successfully. No action is required on your part.", 0),
    ("Please find attached the slides for the security awareness lecture slides.", 0),
    ("The office will be closed on Friday due to national holiday. Enjoy the weekend.", 0),
    ("Here is the recipe for the chocolate cake we talked about. Let me know how it goes.", 0),
    ("Reminder: dentist appointment scheduled for Tuesday at 3:00 PM.", 0),
    ("Confirming your table booking for tonight at 7:30 PM. See you soon.", 0)
]

# Initialize and train ML model in-memory
class PhishingClassifier:
    def __init__(self):
        self.texts = [item[0] for item in TRAINING_DATA]
        self.labels = [item[1] for item in TRAINING_DATA]
        
        # Build NLP Pipeline: TF-IDF Vectorizer + Multinomial Naive Bayes
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                lowercase=True,
                stop_words='english',
                ngram_range=(1, 2), # Use unigrams and bigrams for context
                min_df=1
            )),
            ('clf', MultinomialNB(alpha=0.1)) # Small alpha for Laplace smoothing
        ])
        
        # Train model
        self.pipeline.fit(self.texts, self.labels)

    def predict_phishing(self, subject, body):
        """
        Predicts the probability of text being phishing.
        Returns score from 0.0 to 100.0.
        """
        combined_text = f"{subject} {body}"
        
        # Get probability of class 1 (phishing)
        probabilities = self.pipeline.predict_proba([combined_text])[0]
        phishing_probability = probabilities[1]
        
        # Convert to percentage
        return float(phishing_probability * 100)

# Instantiate the global classifier
_model = None

def get_classifier():
    global _model
    if _model is None:
        _model = PhishingClassifier()
    return _model

def predict(subject, body):
    """Convenience function to get predictions."""
    clf = get_classifier()
    return clf.predict_phishing(subject, body)
