const express = require('express');
const path = require("path");
const Database = require('./db');
const Encryption = require('./aes');
const { hashpassword, verifypassword } = require('./utils/password');
const { generateToken, verifyToken } = require('./middleware/jwt');
// data store like session in flask
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const auth = require("./middleware/auth");
// for flash messages
const session = require("express-session");
const flash = require("connect-flash");
const { error } = require('console');

// for file uploads
const multer = require("multer");
const e = require('connect-flash');




const app = express();
const db = new Database("build_crew");
const encryption = new Encryption();
const port = 3000;

const upload = multer({ storage: multer.memoryStorage()});

// to read form data by using req.body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// to render html files
app.use(express.static(path.join(__dirname, 'public')))

// setting up ejs as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
// setting up flash messages
app.use(session({
  secret: "secret",
  resave: false,
  saveUninitialized: true
}));

app.use(flash());

app.get('/', (req, res) =>{
    res.sendFile(path.join(__dirname, 'public', 'Home.html'));
});

app.route('/company_register')
    .get((req, res) =>{
        res.render("company_register", { mode: "register",result:{}, success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post(upload.single("logo"), async (req, res) =>{
        const data = req.body;
        const{office_mail, contact_person_no, password} = req.body;
        console.log("Submitted Data: ", data);
        const sql = `select * from users where email = ?`;
        const result = await db.fetch_data(sql, [office_mail]);
        if(result && result.role == "COMPANY"){
             console.log("Company already registered with this email");
             req.flash("error", "Company already registered with this email");
             return res.redirect('/company_register');
        }
        const hashedpassword = await hashpassword(password);
        const insert_sql = `insert into users(email, mobile, password_hash, role) values(?, ?, ?, ?)`;
        const insert_result = await db.insert_data(insert_sql, [office_mail, contact_person_no, hashedpassword, "COMPANY"]);
        if(!insert_result){
             req.flash("error", "Error in registering company account");
             return res.redirect('/company_register');
        }else{
            const fetch_sql = `select id from users where email = ?`;
            const fetch_result = await db.fetch_data(fetch_sql, [office_mail]);
            const fetched_user_id = fetch_result.id;
            console.log("Fetched User ID: ", fetched_user_id);
            const {iv, ciphertext, tag} = encryption.encrypt(JSON.stringify(data));
            const company_sql = `insert into companies(user_id, data, nounce, tag) values(?, ?, ?, ?)`;
            const company_insert_result = await db.insert_data(company_sql, [fetched_user_id, ciphertext, iv, tag]);
            if(!company_insert_result){
                req.flash("error", "Error in saving company profile");
                return res.redirect('/company_register');
            }
            req.flash("success", "Company registered successfully");
            return res.redirect('/company_login');
        }
        
    });

app.route('/employee_register')
    .get((req, res) =>{
        res.render("employee_register", { success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post( async (req, res) =>{
       const {name, mobile, email, pass} = req.body;
       console.log("Submitted Data name , mobile, email, password : ", name, mobile, email, pass);
       const sql = `select * from users where email = ?`;
       const result = await db.fetch_data(sql, [email]);
       if(result && result.role == "EMPLOYEE"){
            console.log("Employee already registered with this email");
            req.flash("error", "Employee already registered with this email");
            return res.redirect('/employee_register');
       }
       const hashedpassword = await hashpassword(pass);
       const insert_sql = `insert into users(email, mobile, password_hash, role) values(?, ?, ?, ?)`;
       const insert_result = await db.insert_data(insert_sql, [email, mobile, hashedpassword, "EMPLOYEE"]);
       if(!insert_result){
            req.flash("error", "Error in registering employee account");
            return res.redirect('/employee_register');
       }
       message = "Account Registered Successfully!"
       req.flash("success", "Account registered successfully");
       return res.redirect('/employee_login');
    });


app.route('/company_login')
    .get((req, res) =>{
        res.render("company_login", { success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post( async (req, res) =>{
        const {mail, pass} = req.body;
        const sql = `select * from users where email = ?`;
        const result = await db.fetch_data(sql, [mail]);
        if(!result || result.role !== "COMPANY"){
            req.flash("error", "No company registered with this email");
            return res.redirect('/company_login');
        }
        const check_sql = `select approval_status from companies where user_id = ?`;
        const result_check = await db.fetch_data(check_sql, [result.id]);
        if(result_check.approval_status !== "APPROVED"){
            req.flash("error", "Company not approved yet. Please wait for admin approval.");
            return res.redirect('/company_login');
        }
        const isvalid = await verifypassword(pass, result.password_hash);
        if(!isvalid){
            console.log("Invalid Password");
            req.flash("error", "Invalid Password");
            return res.redirect('/company_login');
        }
        const token = generateToken({
            id: result.id,
            role: result.role
        });
        res.cookie("token", token, {
            httpOnly: true,
            secure: false,   // true in production
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        });
        req.flash("success", "Login Successful");   
        res.redirect("/company_dashboard");
    });


app.route('/company_dashboard')
    .get(auth, async (req, res) => {
        if (!req.isAuth || req.user.role !== "COMPANY") {
            console.log("authentication failed!");
            return res.redirect("/company_login");
        }
        const company_id = req.user.id;
        const status_count = await fetch_hire_status_count(company_id);
        const cmpny_prfl = await fetch_company_profile(company_id);   
        const company_name = cmpny_prfl.companyname;     
        res.render('company_dashboard', {result : cmpny_prfl, status_count, success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post((req, res) => {
        return res.redirect('/company_dashboard');
    });


app.route('/search_workers')
.get(auth, async (req, res) => {
    try {
        if (!req.isAuth || req.user.role !== "COMPANY") {
            console.log("authentication failed!");
            return res.redirect("/company_login");
        }

        const company_id = req.user.id;
        console.log("company id:", company_id);

        const js_alert = req.flash("success")[0] || req.flash("error")[0];
        const cmpny_prfl = await fetch_company_profile(company_id);
        const cmpny_name = cmpny_prfl.companyname;

        const employees = await fetch_all_employees();
        const status_map = await fetch_hire_status_map(company_id);

        let filtered_employees = [];
        let request_sent_count = 0;

        for (const emp of employees) {
            const emp_id = emp.id;
            const status_obj = status_map[emp_id];

            if (status_obj && ["REJECTED", "APPROVED"].includes(status_obj.status)) {
                continue;
            }

            if (status_obj && status_obj.status === "PENDING") {
                request_sent_count++;
            }

            emp.hire_status = status_obj;
            filtered_employees.push(emp);
        }

        console.log("filtered employees:", filtered_employees);
        const success = req.flash("success")[0];
        const error   = req.flash("error")[0];
        res.render("company_search_workers", {
            results: filtered_employees,
            count: request_sent_count,
            profile: cmpny_prfl,
            success: req.flash("success")[0], error: req.flash("error")[0]});

    } catch (err) {
        console.error("GET search_workers error:", err);
        res.redirect("/company_dashboard");
    }
})

.post(auth, async (req, res) => {
    try {
        if (!req.isAuth || req.user.role !== "COMPANY") {
            return res.redirect("/company_login");
        }

        const company_id = req.user.id;
        const cmpny_prfl = await fetch_company_profile(company_id);
        const cmpny_name = cmpny_prfl.companyname;

        const { action, user_id, user_name } = req.body;

        console.log("company id:", company_id);
        console.log("emp id:", user_id);
        console.log("emp name:", user_name);

        if (action === "send_request") {
            const make_hire = `
                INSERT INTO hire_requests (company_id, employee_id)
                VALUES (?, ?)
            `;

            const result = await db.insert_data(make_hire, [company_id, user_id]);
            console.log("make hire finished");

            if (result) {
                req.flash("success", "Hire Request Sent Successfully!");
                const msg = `📨 ${cmpny_name} requested Your Profile`;
                await update_notification(user_id, msg);
            } else {
                req.flash("error", "Error While Sending Hire Request! Try Again...");
            }

            return res.redirect("/search_workers");
        }

        res.redirect("/search_workers");

    } catch (err) {
        console.error("POST search_workers error:", err);
        req.flash("error", "Server Error");
        res.redirect("/search_workers");
    }
});

app.route('/company_hire_requests')
    .get(auth, async (req, res) => {
        try {
            if (!req.isAuth || req.user.role !== "COMPANY") {
                return res.redirect("/company_login");
            }

            const company_id = req.user.id;

            const employees = await fetch_all_employees();
            const status_map = await fetch_hire_status_map(company_id);
            const cmpny_prfl = await fetch_company_profile(company_id);

            let filtered_employees = [];

            for (const emp of employees) {
                const status = status_map[emp.id];

                if (status) {
                    emp.hire_status = status;
                    filtered_employees.push(emp);
                }
            }

            res.render("company_hire_requests", {
                results: filtered_employees,
                profile: cmpny_prfl,
                success: req.flash("success")[0],
                error: req.flash("error")[0]
            });

        } catch (err) {
            console.error(err);
            req.flash("error", "Something went wrong");
            res.redirect("/company_dashboard");
        }
    })



app.route('/company_profile')
    .get(auth, async (req, res) => {
        try {
            if (!req.isAuth || req.user.role !== "COMPANY") {
                return res.redirect("/company_login");
            }

            const cmp_id = req.user.id;

            const results = await fetch_company_profile(cmp_id);

            res.render("company_register", {
                mode: "edit",
                result: results || {},
                success: req.flash("success")[0],
                error: req.flash("error")[0]
            });

        } catch (err) {
            console.error("Error loading company profile:", err);
            req.flash("error", "Unable to load profile");
            res.redirect("/company_dashboard");
        }
    })

    .post(auth, async (req, res) => {
        try {
            if (!req.isAuth || req.user.role !== "COMPANY") {
                return res.redirect("/company_login");
            }

            const cmp_id = req.user.id;

            const data = { ...req.body };
            delete data.action; 

            console.log("Data to update:", data);
            const { iv, ciphertext, tag } = encryption.encrypt(
                JSON.stringify(data)
            );

            const query = `
                UPDATE companies
                SET data = ?, nounce = ?, tag = ?
                WHERE user_id = ?
            `;

            const result = await db.update_data(query, [
                ciphertext,
                iv,
                tag,
                cmp_id
            ]);

            if (result) {
                req.flash("success", "Profile Updated Successfully!");
            } else {
                req.flash("error", "Error while updating profile. Try again.");
            }

            res.redirect("/company_profile");

        } catch (err) {
            console.error("Profile update error:", err);
            req.flash("error", "Something went wrong.");
            res.redirect("/company_profile");
        }
    });



app.route('/view_approved_employees')
    .get(auth, async (req, res) => {
        try {
            if (!req.isAuth || req.user.role !== "COMPANY") {
                return res.redirect("/company_login");
            }

            const company_id = req.user.id;

            const employees = await fetch_all_employees();
            console.log("employees list fetched");

            const cmpny_prfl = await fetch_company_profile(company_id);
            console.log("company profile:", cmpny_prfl);

            const status_map = await fetch_hire_status_map(company_id);
            console.log("status map fetched");

            const filtered_employees = [];

            for (const emp of employees) {
                const emp_id = emp.id;
                const status = status_map[emp_id];

                if (!status || status.status !== "APPROVED") continue;

                emp.hire_status = status;
                filtered_employees.push(emp);
            }

            console.log("approved employees:", filtered_employees);

            res.render("view_approved", {
                results: filtered_employees,
                profile: cmpny_prfl,
                success: req.flash("success")[0],
                error: req.flash("error")[0]
            });

        } catch (err) {
            console.error("Error loading approved employees:", err);
            req.flash("error", "Unable to load approved employees");
            res.redirect("/company_dashboard");
        }
    })



app.route('/employee_login')
    .get((req, res) => {
        res.render("employee_login", { success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post(async (req, res) =>{
        const {email, password} = req.body;
        console.log("submitted email, password : ", email, password);
        const sql = `select * from users where email = ?`;
        const result = await db.fetch_data(sql, [email]);
        if(!result || result.role !== "EMPLOYEE"){
            req.flash("error", "No employee registered with this email");
            return res.redirect('/employee_login');
        }
        const isvalid = await verifypassword(password, result.password_hash);
        if(!isvalid){
            console.log("Invalid Password");
            req.flash("error", "Invalid Password");
            return res.redirect('/employee_login');
        }
        const token = generateToken({
            id: result.id,
            role: result.role
        });

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,   // true in production
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        });

        console.log("role: ", result.role);
        console.log("token: ", req.cookies.token);
        console.log("redirecting to dashboard ");
        req.flash("success", "Login Successful");   
        res.redirect("/employee_dashboard");
    });


app.route('/employee_dashboard')
    .get(auth , async (req, res) => {
        console.log("entered employee dashboard checking for auth user!")
        if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const role = req.user.role;
        let profile_data = await fetch_employee_profile(userId);
        console.log("Fetched Employee Profile Data: ", profile_data);        
        let profile = 0;
        if (profile_data) {
            profile = calculateProfileCompletion(profile_data);
        }
        const authorised = await check_autourised_profile(userId, role);
        const approved_profile = authorised ? 1 : 0;
        let count = 0;
        console.log("Authenticated User ID:", userId, "Role:", role);
        res.render('employee_dashboard',{success:req.flash("success")[0], error:req.flash("error")[0], profile: profile, profile_data: profile_data, count: count, approved_profile: approved_profile });
    })
    .post((req, res) => {
        return res.redirect('/employee_dashboard');
    });    

app.route('/employee_profile')
    .get(auth , async (req, res) => {
        if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const email = await fetch_employee_mail(userId) || null;
        console.log("email for profile: ", email);
        let result = [];
        const profile_data = await fetch_employee_profile(userId);
        if(profile_data){
            result = profile_data;
        }
        console.log("Employee Profile Data to Render: ", result);
        res.render('emp_prfl',{result, experience: result?.experience||[], email: email, step: 0, success:req.flash("success")[0], error:req.flash("error")[0]});
    })
    .post(auth, upload.single("logo"),async (req, res) => {
        const userId = req.user.id;
        console.log("Employee Profile Update Data: ", req.body);

        let data = { ...req.body }; 

        const companies = req.body["company"] || [];
        const locations = req.body["location"] || [];
        const roles = req.body["role"] || [];
        const fromDates = req.body["from"] || [];
        const toDates = req.body["to"] || [];
        const descriptions = req.body["description"] || [];

        let experiences = [];

        for (let i = 0; i < companies.length; i++) {

            if (
                (companies[i] && companies[i].trim()) ||
                (locations[i] && locations[i].trim()) ||
                (roles[i] && roles[i].trim()) ||
                (fromDates[i] && fromDates[i].trim()) ||
                (toDates[i] && toDates[i].trim()) ||
                (descriptions[i] && descriptions[i].trim())
            ) {
                experiences.push({
                    company: companies[i],
                    location: locations[i],
                    role: roles[i],
                    from: fromDates[i],
                    to: toDates[i],
                    description: descriptions[i]
                });
            }
        }

        delete data["company"];
        delete data["location"];
        delete data["role"];
        delete data["from"];
        delete data["to"];
        delete data["description"];

        let cleanData = {};

        Object.keys(data).forEach(key => {
            const value = data[key];

            if (
                value !== null &&
                value !== undefined &&
                value !== '' &&
                value !== '0'
            ) {
                cleanData[key] = value;
            }
        });

        cleanData.experience = experiences;

        if (req.file) {
            cleanData.logo = req.file.filename;  
        }

        // console.log("Final Clean Data Going to DB:", cleanData);

        const {iv, ciphertext, tag} = encryption.encrypt(JSON.stringify(cleanData));
        const exist_user = await check_user(req.user.id, req.user.role);
        console.log("user fetched ");
        console.log("existing user : ", exist_user);
        if(!exist_user){
            const insert_sql = `insert into employees(user_id, data, nounce, tag) values(?, ?, ?, ?)`;
            db.insert_data(insert_sql, [req.user.id, ciphertext, iv, tag]);
        }else{
            const sql = `update employees set data = ?, nounce = ?, tag = ? where user_id = ?`;
            db.update_data(sql, [ciphertext, iv, tag, req.user.id]);
        }
        req.flash("success", "Profile updated successfully");

        return res.redirect('/employee_profile');
    });


app.get('/employee_personal', auth , async (req, res) => {
    if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const email = await fetch_employee_mail(userId) || null;
        console.log("email for profile: ", email);
        let result = [];
        const profile_data = await fetch_employee_profile(userId);
        if(profile_data){
            result = profile_data;
        }
        res.render('emp_prfl',{result, experience: result?.experience||[], email:email, step: 0, success:req.flash("success")[0], error:req.flash("error")[0]});
});

app.get('/employee_professional', auth , async (req, res) => {
    if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const email = await fetch_employee_mail(userId) || null;
        console.log("email for profile: ", email);
        let result = [];
        const profile_data = await fetch_employee_profile(userId);
        if(profile_data){
            result = profile_data;
        }
        res.render('emp_prfl',{result, experience: result?.experience||[], email:email, step: 1, success:req.flash("success")[0], error:req.flash("error")[0]});
});

app.get('/employee_certifications', auth , async (req, res) => {
    if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const email = await fetch_employee_mail(userId) || null;
        console.log("email for profile: ", email);
        let result = [];
        const profile_data = await fetch_employee_profile(userId);
        if(profile_data){
            result = profile_data;
        }
        res.render('emp_prfl',{result, experience: result?.experience||[], email:email, step: 2, success:req.flash("success")[0], error:req.flash("error")[0]});
});

app.get('/employee_contact', auth , async (req, res) => {
    if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        const userId = req.user.id;
        const email = await fetch_employee_mail(userId) || null;
        console.log("email for profile: ", email);
        let result = [];
        const profile_data = await fetch_employee_profile(userId);
        if(profile_data){
            result = profile_data;
        }
        res.render('emp_prfl',{result, experience: result?.experience||[], email:email, step: 3, success:req.flash("success")[0], error:req.flash("error")[0]});
});


app.route('/employee_notifications')
    .get(auth, async (req, res) => {
        if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        emp_id = req.user.id;
        emp_prfl = await fetch_employee_profile(emp_id);
        let count = 0
        const count_result = await notification_count(emp_id);
        if(count_result > 0){
            count = count_result;
        } 
        const notifications = await fetch_notifications(emp_id); 
        console.log("Notifications: ", notifications); 
        res.render('employee_notifications', {profile_data: emp_prfl, results: notifications, count: count, success: req.flash("success")[0], error: req.flash("error")[0] });
    })
    .post((req, res) => {});

app.route('/make_request')
    .get(auth, (req, res) => {
        if (!req.isAuth || req.user.role !== "EMPLOYEE") {
            console.log("authentication failed!");
            return res.redirect("/employee_login");
        }
        prfl = fetch_employee_profile(req.user.id);
        res.render('Request', {profile_data: prfl, success: req.flash("success")[0], error: req.flash("error")[0] });
    })
    .post(auth, async (req, res) => {
        try {
            const emp_id = req.user.id;
            const data = { ...req.body };
            const jsonData = JSON.stringify(data);
            const { ciphertext, iv, tag } = encryption.encrypt(jsonData);
            const sql = `
                INSERT INTO work_requests (user_id, message, nounce, tag)
                VALUES (?, ?, ?, ?)
            `;

            const result = await db.insert_data(sql, [
                emp_id,
                ciphertext,
                iv,       
                tag
            ]);
            if (result) {
                req.flash("success", "Request Sent To Admin");
            } else {
                req.flash("error", "Error While Making Request! Try Again Later...");
            }

            return res.redirect("/make_request");

        } catch (err) {
            console.error("Work request error:", err);
            req.flash("error", "Server Error");
            return res.redirect("/make_request");
        }
    });


app.route('/admin_login')
    .get((req, res) =>{
        res.render("admin_login", { success: req.flash("success")[0], error: req.flash("error")[0]});
    })
    .post( async (req, res) => {
        const {email, password} = req.body;
        const sql = `select * from users where email = ?`;
        const result = await db.fetch_data(sql, [email]);
        if(!result || result.role !== "ADMIN"){
            req.flash("error", "No admin registered with this email");
            return res.redirect('/admin_login');
        }
        const isvalid = await verifypassword(password, result.password_hash);
        if(!isvalid){
            console.log("Invalid Password");
            req.flash("error", "Invalid Password");
            return res.redirect('/admin_login');
        }
        const token = generateToken({
            id: result.id,
            role: result.role
        });

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,   // true in production
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        });

        console.log("role: ", result.role);
        console.log("token: ", req.cookies.token);
        console.log("redirecting to dashboard ");
        req.flash("success", "Login Successful");   
        res.redirect("/admin_dashboard");
    });


app.route('/admin_dashboard')
    .get( auth ,async (req, res) =>{
        if (!req.isAuth || req.user.role !== "ADMIN") {
            console.log("authentication failed!");
            return res.redirect("/admin_login");
        }
        const count = await work_request_count();
        const result =  {
            "employees": await fetch_employees(),
            "companies": await fetch_companies(),
            "pending": await pending_approval_count(),
            "request": await fetch_hire_request_count(),
            "all_employees" : await fetch_all_employees(),
            "all_companies" : await fetch_all_companies()
        };
        console.log("Admin Dashboard Data: ", result);
        res.render('admin_dashboard', {result: result, count: count, success:req.flash("success")[0], error:req.flash("error")[0]});
    })
    .post((req, res) => {
        return res.redirect('/admin_dashboard');
    });    

app.route('/users_approval')
.get(auth,async (req, res) =>{
    if (!req.isAuth || req.user.role !== "ADMIN") {
        console.log("authentication failed!");
        return res.redirect("/admin_login");
    }
    const pending_requests = await pending_approvals();
    res.render('admin_users_approval',{ result:pending_requests, success:req.flash("success")[0], error:req.flash("error")[0]})

})
.post(auth, async (req, res)=>{
    let {user_type, user_id, action} = req.body;
    let table = "";
    if(user_type == "employee"){
        table = "employees";
    }else if(user_type == "company"){
        table = "companies";
    }
    const status = action === "approve" ? "APPROVED" : "REJECTED"
    const query = ` UPDATE ${table} SET approval_status = ? WHERE user_id = ? `
    const result = db.update_data(query, [status, user_id])
    if(result){
        req.flash("success", `${user_type} ${status} Successfully`); 
        return res.redirect('/users_approval');
        
    } else {
        req.flash("error", "Error While Update");
        return res.redirect('/users_approval');
    }
    
});


app.route('/hire_requests')
.get(auth, async (req, res) =>{
    if (!req.isAuth || req.user.role !== "ADMIN") {
        console.log("authentication failed!");
        return res.redirect("/admin_login");
    }
    console.log("entered hire requests");
    const hire_requests = await fetch_hire_request();
    res.render('admin_hire_requests', {results : hire_requests, success:req.flash("success")[0], error:req.flash("error")[0]})

})
app.post("/hire_requests", auth, async (req, res) => {
    try {
        const { action, emp_id, cmpny_name, notification_id } = req.body;

        console.log("emp id :", emp_id);
        console.log("cmpny name :", cmpny_name);
        console.log("notify id :", notification_id);
        console.log("action :", action);

        if (action === "approve") {

            const query = `
                UPDATE hire_requests 
                SET request_status = ?, contact_shared = ? 
                WHERE id = ?
            `;

            const result = await db.update_data(query, ["APPROVED", 1, notification_id]);

            if (result) {
                req.flash("success", "Hire Request Approved!");

                const msg = `✅ Hire request approved. Your contact details were shared to ${cmpny_name}`;
                await update_notification(emp_id, msg);

                return res.redirect("/hire_requests");
            }

        } else if (action === "reject") {

            const query = `
                UPDATE hire_requests 
                SET request_status = ? 
                WHERE id = ?
            `;

            const result = await db.update_data(query, ["REJECTED", notification_id]);

            if (result) {
                req.flash("error", "Hire Request Removed!");
                return res.redirect("/hire_requests");
            }
        }

        // fallback
        req.flash("error", "Something went wrong");
        res.redirect("/hire_requests");

    } catch (err) {
        console.error("Hire request error:", err);
        req.flash("error", "Server error");
        res.redirect("/hire_requests");
    }
});


app.route('/work_request')
.get(auth,async (req, res) =>{
    if (!req.isAuth || req.user.role !== "ADMIN") {
        console.log("authentication failed!");
        return res.redirect("/admin_login");
    }
    console.log("entered work request");
    const results = await fetch_work_request();
    console.log("work request fetched");
    const count = await work_request_count();
    console.log("work request count fetched");
    let enriched_results = [];
    for (const req of results){
        const emp_id = req.user_id;
        const emp_prfl = fetch_employee_profile(emp_id) || {};
        req["employee"] = emp_prfl;
        enriched_results.push({
            ...req,
            employee: emp_prfl
        });
    }
    res.render('view_work_request', {results : enriched_results, count, success:req.flash("success")[0], error:req.flash("error")[0]})
})
.post(auth, async (req, res)=>{
    try {
        const { action, user_id, title } = req.body;

        console.log(action, title);

        let message = "";
        let status = "";

        if (action === "approve") {
            message = `Your Request for ${title}, Work Approved By Admin And Your Profile Will Be Shared to Companies...`;
            status = "APPROVED";
        } else {
            message = `Your Request for ${title}, Work Has Been Rejected By Admin!`;
            status = "REJECTED";
        }

        const query = `
            INSERT INTO notifications (user_id, message, request_status)
            VALUES (?, ?, ?)
        `;

        const result = await db.insert_data(query, [user_id, message, status]);

        if (result) {
            req.flash("success", action === "approve"
                ? "Work Request Approved"
                : "Work Request Removed"
            );
        } else {
            req.flash("error", "Oops! Error occurred");
        }

        res.redirect("/work_request");

    } catch (err) {
        console.error("Work request action error:", err);
        req.flash("error", "Server error");
        res.redirect("/work_request");
    }
});



app.get("/view_employee_profile/:emp_id", auth, async (req, res) => {
    try {
        const empId = req.params.emp_id;
        console.log("entered view_employee_profile");
        console.log("emp id : ", empId);

        let emp_profile = await fetch_employee_profile(empId);

        if (!emp_profile) {
            req.flash("error", "Employee not found");
            return res.redirect("/admin_dashboard");
        }

        const toList = (value) => {
            if (Array.isArray(value)) return value;
            if (typeof value === "string") {
                return value.split(",").map(v => v.trim()).filter(v => v);
            }
            return [];
        };

        emp_profile.secondarySkills = toList(emp_profile.secondarySkills);
        emp_profile.Tools = toList(emp_profile.Tools);
        emp_profile.Certificates = toList(emp_profile.Certificates);

        res.render("view_employee", {
            employee: emp_profile,
            emp_id: empId,
            success: req.flash("success")[0],
            error: req.flash("error")[0]
        });

    } catch (err) {
        console.error(err);
        req.flash("error", "Server error");
        res.redirect("/admin_dashboard");
    }
});


app.get('/employee/:emp_id', auth, async (req, res) => {
    try {
        console.log("entered employee/emp:id route");
        const empId = req.params.emp_id;
        console.log("employee id: ", empId);

        const emp_profile = await fetch_employee_profile(empId);
        console.log("fetched employee profile");
        if (!emp_profile) {
            req.flash("error", "Employee profile not found");
            return res.redirect("/admin_dashboard");
        }
        console.log("fetching mail");
        const email = await fetch_employee_mail(empId) || null;
        res.render('employee_profile', { result: emp_profile, experience: emp_profile?.experience||[], step: 0,  emp_id: empId, email:email, success: req.flash("success")[0], error: req.flash("error")[0] });

    } catch (err) {
        console.error(err);
        req.flash("error", "Server error");
        res.redirect("/admin_dashboard");
    }
});


app.get('/view_company_profile/:cmp_id', auth, async (req, res) => {
    const cmp_id = req.params.cmp_id;
    const cmp_profile = await fetch_company_profile(cmp_id);
    console.log("fetched company profile : ", cmp_profile);
    res.render('view_company', {company: cmp_profile, cmp_id, success: req.flash("success")[0], error: req.flash("error")[0] })
})

app.get('/company/:cmp_id' , auth, async (req, res) =>{
    const cmp_id = req.params.cmp_id;
    const cmp_profile = await fetch_company_profile(cmp_id);
    console.log("fetched company profile : ", cmp_profile);
    res.render('company_profile', {result : cmp_profile, cmp_id})
})  


app.route('/back')
    .get( auth ,(req, res) =>{
        const user = req.user.role;
        if(user == "ADMIN"){
            return res.redirect('/admin_dashboard');
        }else if(user == "COMPANY"){
            return res.redirect('/company_dashboard');
        }else if(user == "EMPLOYEE"){
            return res.redirect('/employee_dashboard');
        }
    });

app.route('/logout')
    .get((req, res) =>{
        res.clearCookie("token");
        return res.redirect('/');
    });

async function notification_count(user_id){
    const sql = `select count(*) from notifications where user_id = ?`;
    const result = await db.fetch_all_data(sql, [user_id]);
    if(result){
        return result.length ? result[0].total : 0;
    }else{ return 0 }
}

async function fetch_notifications(user_id){
    const sql = `select * from notifications where user_id = ?`;
    const result = await db.fetch_all_data(sql, [user_id]);
    if(result){
        return result;
    }else{ return [] }
}


async function update_notification(id, msg) {
    try {
        const query = `
            INSERT INTO notifications (user_id, message)
            VALUES (?, ?)
        `;

        const result = await db.insert_data(query, [id, msg]);

        return !!result;

    } catch (err) {
        console.error("update_notification error:", err);
        return false;
    }
}


async function fetch_employee_profile(emp_id){
    const sql = `select * from employees where user_id = ?`;
    const result = await db.fetch_data(sql, [emp_id]);
    if(result){
        const iv = result.nounce;
        const data = result.data;
        const tag = result.tag;
        const decrypted_data = encryption.decrypt(iv, data, tag);
        if(decrypted_data){
            const emp_profile = JSON.parse(decrypted_data);
            return emp_profile;
        }
    }else{ return [] }
}


async function fetch_company_profile(companyId) {
    try {
        const fetchQuery = "SELECT * FROM companies WHERE user_id = ?";
        const result = await db.fetch_data(fetchQuery, [companyId]);
        if (!result) {
            return [];
        }
        const encryptedData = result.data;
        const iv = result.nounce;
        const tag = result.tag;

        const decryptedData = encryption.decrypt(iv,encryptedData, tag);

        return JSON.parse(decryptedData);

    } catch (error) {
        console.error("Error fetching company profile:", error);
        return [];
    }
}



async function fetch_employee_mail(user_id) {
    const sql = `select email from users where id = ?`;
    const result = await db.fetch_data(sql, [user_id]);
    console.log("User ID for Email Fetch: ", user_id);
    console.log("Fetched Employee Email Result: ", result);
    if(result){
        return result.email;
    }else{ return null }
}

async function work_request_count(){
    const sql = `select count(*) as total from work_requests where request_status = 'PENDING'`;
    const result = await db.fetch_data_without_value(sql);
    if(result){
        return result.length ? result[0].total : 0;
    }else{ return 0 }
}

async function fetch_employees(){
    const sql = `select count(*) from employees where role = 'EMPLOYEE' and approval_status = 'APPROVED'`;
    const result = await db.fetch_data_without_value(sql);
    console.log("Employee Count Result: ", result);
    let employeeCount = 0;

    if (Array.isArray(result) && result.length > 0) {
        employeeCount = result[0]["count(*)"];
    }

    console.log("Confirmed employee count:", employeeCount);
    return employeeCount;
}

async function fetch_companies(){
    const sql = `select count(*) from companies where approval_status = 'APPROVED'`;
    const result = await db.fetch_data_without_value(sql);
    console.log("Company Count Result: ", result);
    let companyCount = 0;

    if (Array.isArray(result) && result.length > 0) {
        companyCount = result[0]["count(*)"];
    }

    console.log("Confirmed company count:", companyCount);
    return companyCount;
}

async function pending_approval_count(){
    const sql = `select count(*)  from companies where approval_status = 'PENDING'`;
    const result = await db.fetch_data_without_value(sql);
    const sql2 = `select count(*)  from employees where approval_status = 'PENDING'`;
    const result2 = await db.fetch_data_without_value(sql2);
    console.log("Pending Companies Count Result: ", result);
    console.log("Pending Employees Count Result: ", result2);
    if(result && result2){
        const company_count = result.length ? result[0]["count(*)"]: 0;
        const employee_count = result2.length ? result2[0]["count(*)"] : 0;
        return company_count +employee_count;
    }else{ return 0 }
}


async function fetch_hire_request() {
    try {
        const fetchQuery = `
            SELECT id, company_id, employee_id, created_at
            FROM hire_requests
            WHERE request_status = 'PENDING'
        `;

        const results = await db.fetch_data_without_value(fetchQuery);
        console.log("fetch hire results :", results);

        const hireRequests = [];

        for (const row of results) {
            const id = row.id;
            const cmp_id = row.company_id;
            const emp_id = row.employee_id;
            const created_time = row.created_at;

            const cmp_prfl = await fetch_company_profile(cmp_id);
            const emp_prfl = await fetch_employee_profile(emp_id);

            if (cmp_prfl && Object.keys(cmp_prfl).length > 0) {
                cmp_prfl.company_id = cmp_id;
            }

            if (emp_prfl && Object.keys(emp_prfl).length > 0) {
                emp_prfl.employee_id = emp_id;
            }

            hireRequests.push({
                request_id: id,
                emp_prfl: emp_prfl || {},
                cmp_prfl: cmp_prfl || {},
                created_at: created_time
            });
        }

        return hireRequests;

    } catch (error) {
        console.error("Error fetching hire requests:", error);
        return [];
    }
}



async function fetch_hire_request_count(){
    const sql = `select count(*) as total from hire_requests where request_status = 'PENDING'`;
    const result = await db.fetch_data_without_value(sql);
    if(result){
        return result.length ? result[0].total : 0;
    }else{ return 0 }
}

async function fetch_hire_status_count(company_id) {
    try {
        console.log("function called");

        const query = `
            SELECT request_status, COUNT(*) AS total
            FROM hire_requests
            WHERE company_id = ?
            GROUP BY request_status
        `;

        const rows = await db.fetch_all_data(query, [company_id]);
        console.log("rows:", rows);
        const counts = {
            PENDING: 0,
            APPROVED: 0,
            REJECTED: 0
        };
        for (const row of rows) {
            counts[row.request_status] = row.total;
        }

        console.log("counts:", counts);
        return counts;

    } catch (err) {
        console.error("fetch_hire_status_count error:", err);
        return {
            PENDING: 0,
            APPROVED: 0,
            REJECTED: 0
        };
    }
}

async function fetch_hire_status_map(company_id) {
    try {
        const query = `
            SELECT employee_id, request_status, updated_at
            FROM hire_requests
            WHERE company_id = ?
        `;

        const rows = await db.fetch_all_data(query, [company_id]);

        const statusMap = {};

        for (const row of rows) {
            statusMap[row.employee_id] = {
                status: row.request_status,
                updated_at: row.updated_at
            };
        }

        return statusMap;

    } catch (err) {
        console.error("fetch_hire_status_map error:", err);
        return {};
    }
}


async function fetch_all_employees(){
    const sql = `select * from employees where role = 'EMPLOYEE' and approval_status = 'APPROVED'`;
    const result = await db.fetch_data_without_value(sql);
    console.log("All Employees Result: ", result);
    const employee_data = [];
    for(const row of result){
        const iv = row.nounce;
        const data = row.data;
        const tag = row.tag;
        const decrypted_data = encryption.decrypt(iv, data, tag);
        if(decrypted_data){
            const employee_profile = JSON.parse(decrypted_data);
            employee_profile.id = row.user_id;
            employee_data.push(employee_profile);
        }
    }
    // console.log("employee data  : ", employee_data);
    return employee_data;
}
async function fetch_all_companies(){
    const sql = `select * from companies where role = 'COMPANY' and approval_status = 'APPROVED'`;
    const result = await db.fetch_data_without_value(sql);
    console.log("All Companies Result: ", result);
    const company_data = [];
    for(const row of result){
        const iv = row.nounce;
        const data = row.data;
        const tag = row.tag;
        const decrypted_data = encryption.decrypt(iv, data, tag);
        if(decrypted_data){
            const company_profile = JSON.parse(decrypted_data);
            company_profile.id = row.user_id;
            company_data.push(company_profile);
        }
    }
    return company_data;
}

async function check_user(user_id, role){
    if(role == "EMPLOYEE"){
        const sql = `select * from employees where user_id = ?`;
        const result = await db.fetch_data(sql, [user_id]);
        if(result){
            return true;
        }else{
            return false;
        }
    }else if(role == "COMPANY"){
        const sql = `select * from companies where user_id = ?`;
        const result = await db.fetch_data(sql, [user_id]);
        if(result){
            return true;
        }else{
            return false;
        }
    }
}

async function pending_approvals() {
    const companyQuery = `SELECT * FROM companies WHERE approval_status = 'PENDING'`;
    const companyResult = await db.fetch_data_without_value(companyQuery);

    const employeeQuery = `SELECT * FROM employees WHERE approval_status = 'PENDING'`;
    const employeeResult = await db.fetch_data_without_value(employeeQuery);

    const company_decrypted = [];
    const employee_decrypted = [];

    for (const row of companyResult) {
        try {
            const iv = row.nounce;    
            const data = row.data;    
            const tag = row.tag;    

            const decrypted = encryption.decrypt(iv, data, tag);
            const cmp_data = JSON.parse(decrypted);

            cmp_data.id = row.user_id;   
            cmp_data.role = row.role;   

            company_decrypted.push(cmp_data);
        } catch (err) {
            console.error("Company decrypt error:", err);
        }
    }

    for (const row of employeeResult) {
        try {
            const iv = row.nounce;
            const data = row.data;
            const tag = row.tag;

            const decrypted = encryption.decrypt(iv, data, tag);
            const emp_data = JSON.parse(decrypted);

            emp_data.id = row.user_id;
            emp_data.role = row.role;

            employee_decrypted.push(emp_data);
        } catch (err) {
            console.error("Employee decrypt error:", err);
        }
    }

    return {
        companies: company_decrypted,
        employees: employee_decrypted
    };
}


async function fetch_work_request() {
    try {
        const query = "SELECT * FROM work_requests WHERE request_status = 'PENDING'";
        const rows = await db.fetch_data_without_value(query);

        const work_requests = [];

        if (rows && rows.length > 0) {
            for (const row of rows) {

                const user_id = row.user_id;
                const encryptedData = row.message;
                const iv = row.nounce;
                const tag = row.tag;

                const decryptedString = encryption.decrypt(iv, encryptedData, tag);
                const decryptedData = JSON.parse(decryptedString);

                decryptedData.user_id = user_id;

                const emp_profile = await fetch_employee_profile(user_id);

                if (emp_profile) {
                    decryptedData.employee = emp_profile;        
                    decryptedData.employee_name = emp_profile.Name;
                }

                work_requests.push(decryptedData);
            }
        }

        console.log("Work Requests with Employee:", work_requests);
        return work_requests;

    } catch (err) {
        console.error("fetch_work_request error:", err);
        return [];
    }
}



async function check_autourised_profile(user_id, role){
    if(role == "EMPLOYEE"){
        const sql = `select approval_status from employees where user_id = ?`;
        const result = await db.fetch_data(sql, [user_id]);
        if(result){
            if(result.approval_status == "APPROVED"){
                return true;
            }else{
                return false;
            }
        }else{
            return false;
        }
    }
}

function calculateProfileCompletion(employee) {
    if (!employee) return 0;

    const profileFields = [
        'profile_pic',
        'Name',
        'dob',
        'Gender',
        'Aadhar',
        'Address',
        'Languages',
        'Field',
        'experience_year',
        'Skill',
        'secondarySkills',
        'Tools',
        'Current_Company',
        'Availability',
        'Certificates',
        'Mobile',
        'Email'
    ];

    let filledFields = 0;

    profileFields.forEach(field => {
        const value = employee[field];

        if (
            value !== null &&
            value !== undefined &&
            value !== '' &&
            value !== '0' &&
            !(Array.isArray(value) && value.length === 0)
        ) {
            filledFields++;
        }
    });

    return Math.round((filledFields / profileFields.length) * 100);
}


app.listen(port,() => {
    console.log(`Server is running on http://localhost:${port}`);
});