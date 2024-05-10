import streamlit as st
from streamlit_modal import Modal
from streamlit_option_menu import option_menu
import thekingphishers as kp
import pickle
import pandas as pd

top_safe_domains = ['google.com', 'flipkart.com', 'facebook.com', 'whatsapp.com', 'instagram.com', 'amazon.in',
                    'education.gov.in', 'steampowered.com', 'streamlit.io', 'discord.com', 'github.com', 'irctc.co.in',
                    'bing.com', 'bank.sbi', 'onlinesbi.sbi']
tld = ['gov.in']
st.set_page_config(page_title="Phishing Detector", page_icon=":shield:")

with open('svm_model.pkl', 'rb') as svm:
    svm_model = pickle.load(svm)

with open('lr_model.pkl', 'rb') as lr:
    lr_model = pickle.load(lr)

def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

local_css("style.css")

st.title("Phishing Detector")

selected = option_menu(
    menu_title=None,
    options=["Home", "Detector", "About Us", "Contact"],
    icons=["house", "search", "envelope", "telephone"],
    menu_icon="cast",
    default_index=0,
    orientation="horizontal")

if selected == "Home":
    st.image("king.png", width=700)
    st.write("Welcome to our phishing detection tool, created by The KingPhishers!")
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)

if selected == "Detector":
    st.header("Website URL Detector")
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Choose a file", type=["txt"])

    if uploaded_file is not None:
        content = uploaded_file.getvalue().decode("utf-8")
        urls = content.split('\n')
        for input_url in urls:
            if not input_url:
                continue

            checking_message = st.info(f"Checking {input_url}... Please wait")

            safe = False
            final_url = kp.get_final_url(input_url)
            domain = kp.get_domain_from_url(input_url)
            final_domain = kp.get_domain_from_url(final_url)
            domain1 = kp.get_tld_from_url(input_url)
            final_domain1 = kp.get_tld_from_url(final_url)

            if domain in top_safe_domains or final_domain in top_safe_domains or domain1 in tld or final_domain1 in tld:
                safe = True

            if safe:
                final_prediction = "Safe"
            else:
                features = kp.analyze_website(final_url)
                are_all_minus_1 = all(x == -1 for x in features)
                if are_all_minus_1:
                    final_prediction = ""
                else:
                    weight_classifier = 0.7
                    weight_pipeline_ls = 0.3

                    pred_classifier = svm_model.predict([features])
                    pred_pipeline_ls = lr_model.predict([input_url])
                    weighted_average_pred = (
                                weight_classifier * int(pred_classifier[0]) + weight_pipeline_ls * int(
                            pred_pipeline_ls[0])) / (weight_classifier + weight_pipeline_ls)
                    threshold = 0.3

                    if weighted_average_pred > 0.4:
                        final_prediction = "Safe"
                    elif 0.29 < weighted_average_pred <= 0.4:
                        final_prediction = "Suspicious"
                        no_1 = sum(1 for ft in features if ft == 1)
                        score = (no_1 / 7) * 100
                        score = round(score, 2)
                    else:
                        final_prediction = "Phishing"
                        no_1 = sum(1 for ft in features if ft == 1)
                        score = (no_1 / 7) * 100
                        score = round(score, 2)

            if final_prediction == "Safe":
                if checking_message:
                    checking_message.empty()
                url = input_url
                link_text = input_url
                st.success(f'This website is safe! Click {link_text}.')
            elif final_prediction == "Suspicious":
                if checking_message:
                    checking_message.empty()
                st.warning("This website is suspicious!")
                st.write(
                    "The given suspicious website scores " + str(score) + "% in its similarity to genuine domains")
            elif final_prediction == "Phishing":
                if checking_message:
                    checking_message.empty()
                st.warning("This website is phishing!")
                st.write("The given phishing website scores " + str(score) + "% in its similarity to genuine domains")
                st.markdown("""
                            <div style="text-align: center;">
                            <img src="https://www.pngall.com/wp-content/uploads/8/Red-Warning-PNG.png" width="100" height="80">
                            <h4>Warning!</h4>
                            <p>The given URL is suspicious. Please click the report button to report the URL.</p>
                            <a href="https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en" target="_blank">
                                <button>Report</button>
                            </a>
                                </div>
                            """, unsafe_allow_html=True)
            else:
                if checking_message:
                    checking_message.empty()
                st.error("Error: Request Failed | Unable to make a prediction | Please enter valid URL")

if selected == "About Us":
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)
    st.header("About Us")
    st.write(
        "Kingphishers is a dynamic team of six talented students who have harnessed their collective expertise to create a cutting-edge phishing website detector. With a shared passion for cybersecurity and a commitment to protecting individuals and organizations from online threats, our team has worked tirelessly to develop a sophisticated tool that identifies and safeguards against phishing scams. Through collaboration, innovation, and a dedication to staying one step ahead of cybercriminals, Kingphishers is on a mission to make the digital world a safer place for everyone.")
    st.write("This is our submission for the Smart India Hackathon 2023.")

if selected == "Contact":
    with st.container():
        st.header("Get In Touch With Us!")
        st.write("##")

        contact_form = """
        <form action="https://formsubmit.co/aashman.dc@gmail.com" method="POST">
            <input type="hidden" name="_captcha" value="false">
            <input type="text" name="name" placeholder="Your name" required>
            <input type="email" name="email" placeholder="Your email" required>
            <textarea name="message" placeholder="Your message here" required></textarea>
            <button type="submit">Send</button>
        </form>
        """

        left_column, right_column = st.columns(2)
        with left_column:
            st.markdown(contact_form, unsafe_allow_html=True)
        with right_column:
            st.empty()

hide_streamlit_style = """
    <style>
        footer {visibility: Hidden;}
        header {visibility: Hidden;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)
