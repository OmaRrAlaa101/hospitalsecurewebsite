-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 24, 2025 at 07:17 AM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `secure_health`
--

-- --------------------------------------------------------

--
-- Table structure for table `appointments`
--

CREATE TABLE `appointments` (
  `id` int(11) NOT NULL,
  `patient_id` int(11) NOT NULL,
  `doctor_id` int(11) NOT NULL,
  `appointment_time` datetime NOT NULL,
  `status` enum('scheduled','completed','cancelled') DEFAULT 'scheduled',
  `reason` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `appointments`
--

INSERT INTO `appointments` (`id`, `patient_id`, `doctor_id`, `appointment_time`, `status`, `reason`, `created_at`, `updated_at`) VALUES
(4, 9, 4, '2025-05-07 05:33:00', 'cancelled', 'help mee', '2025-05-24 02:34:03', '2025-05-24 03:01:09'),
(5, 9, 4, '2025-05-06 06:02:00', 'scheduled', 'dont leave me', '2025-05-24 03:02:50', '2025-05-24 03:02:50');

-- --------------------------------------------------------

--
-- Table structure for table `audit_logs`
--

CREATE TABLE `audit_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(50) NOT NULL,
  `entity_type` varchar(50) DEFAULT NULL,
  `entity_id` int(11) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `details` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `audit_logs`
--

INSERT INTO `audit_logs` (`id`, `user_id`, `action`, `entity_type`, `entity_id`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES
(1, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 21:53:42'),
(2, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 21:56:20'),
(3, 4, 'BOOK_APPOINTMENT', NULL, NULL, '127.0.0.1', NULL, 'With doctor ID: 2', '2025-05-23 21:57:24'),
(4, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 21:58:40'),
(5, 4, 'BOOK_APPOINTMENT', NULL, NULL, '127.0.0.1', NULL, 'With doctor ID: 2', '2025-05-23 21:58:52'),
(6, 4, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 21:59:06'),
(7, NULL, 'LOGIN_FAILED', NULL, NULL, '127.0.0.1', NULL, 'Failed login for admin@securehealth.com', '2025-05-23 22:18:51'),
(8, 1, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:26:04'),
(9, 1, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:28:23'),
(10, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:28:54'),
(11, 1, 'DEACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:29:05'),
(12, 1, 'ACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:29:33'),
(13, 1, 'DEACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 1', '2025-05-23 22:29:35'),
(14, 1, 'ACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 1', '2025-05-23 22:29:44'),
(15, NULL, 'LOGIN_FAILED', NULL, NULL, '127.0.0.1', NULL, 'Failed login for admin', '2025-05-23 22:37:32'),
(16, 1, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:38:44'),
(17, 1, 'DEACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:38:55'),
(18, 4, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:39:18'),
(19, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:39:32'),
(20, 1, 'ACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:39:36'),
(21, 1, 'DEACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:39:41'),
(22, 1, 'ACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:41:48'),
(23, 1, 'DEACTIVATED_USER', NULL, NULL, '127.0.0.1', NULL, 'User ID: 4', '2025-05-23 22:42:14'),
(24, 4, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:42:21'),
(25, 1, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:42:24'),
(26, 1, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:42:42'),
(27, 4, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:42:51'),
(28, 4, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 22:42:57'),
(29, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 22:47:41'),
(30, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 22:47:50'),
(31, 1, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:02:15'),
(32, NULL, 'LOGIN_FAILED', NULL, NULL, '127.0.0.1', NULL, 'Failed login for admin', '2025-05-23 23:11:27'),
(33, NULL, 'LOGIN_FAILED', NULL, NULL, '127.0.0.1', NULL, 'Failed login for admin', '2025-05-23 23:12:17'),
(34, 1, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:13:27'),
(35, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:13:31'),
(36, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:13:38'),
(37, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:14:03'),
(38, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:14:18'),
(39, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:24:22'),
(40, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:24:25'),
(41, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:24:41'),
(42, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:02'),
(43, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:25:08'),
(44, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:12'),
(45, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:25:15'),
(46, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:16'),
(47, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:25:21'),
(48, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:23'),
(49, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:25:23'),
(50, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:24'),
(51, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:25:28'),
(52, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:25:32'),
(53, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:26:40'),
(54, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:26:44'),
(55, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:26:56'),
(56, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to inactive', '2025-05-23 23:27:00'),
(57, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user Ahmed to active', '2025-05-23 23:27:01'),
(58, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user mariam to inactive', '2025-05-23 23:27:37'),
(59, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user mariam to active', '2025-05-23 23:27:39'),
(60, 1, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user admin to inactive', '2025-05-23 23:28:53'),
(61, 5, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:30:24'),
(62, 5, 'TOGGLE_USER', NULL, NULL, '127.0.0.1', NULL, 'Toggled user admin to active', '2025-05-23 23:30:27'),
(63, 4, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:32:10'),
(64, 4, 'ADD_RECORD', NULL, NULL, '127.0.0.1', NULL, 'For patient ID: 9', '2025-05-23 23:32:42'),
(65, 9, 'LOGIN_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:33:38'),
(66, 9, 'BOOK_APPOINTMENT', NULL, NULL, '127.0.0.1', NULL, 'With doctor ID: 4', '2025-05-23 23:34:03'),
(67, 5, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:42:25'),
(68, 4, '2FA_SUCCESS', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-23 23:42:45'),
(69, 4, 'DELETE_RECORD', NULL, NULL, '127.0.0.1', NULL, 'Record ID: 2', '2025-05-23 23:59:26'),
(70, 4, 'ADD_RECORD', NULL, NULL, '127.0.0.1', NULL, 'For patient ID: 8', '2025-05-23 23:59:42'),
(71, 9, 'CANCEL_APPOINTMENT', NULL, NULL, '127.0.0.1', NULL, 'Appointment ID: 4', '2025-05-24 00:01:09'),
(72, 9, 'BOOK_APPOINTMENT', NULL, NULL, '127.0.0.1', NULL, 'With doctor ID: 4', '2025-05-24 00:02:50'),
(73, 9, 'LOGOUT', NULL, NULL, '127.0.0.1', NULL, '', '2025-05-24 00:13:20');

-- --------------------------------------------------------

--
-- Table structure for table `patient_records`
--

CREATE TABLE `patient_records` (
  `id` int(11) NOT NULL,
  `patient_id` int(11) NOT NULL,
  `doctor_id` int(11) NOT NULL,
  `diagnosis` text NOT NULL,
  `prescription` text DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `patient_records`
--

INSERT INTO `patient_records` (`id`, `patient_id`, `doctor_id`, `diagnosis`, `prescription`, `notes`, `created_at`, `updated_at`) VALUES
(3, 8, 4, 'gAAAAABoMTYedoH9ENtkARRlzkiViQbXzemoG37KJAA7eLLhLIJ_ITrxLZb6z50orgmzTtEcG_MbUr0VMppvUnfhfEUTThbW_A==', 'gAAAAABoMTYeaOOJ3ghkaMLQOqasATDIRvNzr4jMLzyeqFsMNIP_fcbwXHb6N4Ufn7TFaxaLsh3dNxWg6ErVAVHgaJE1Lc2gYA==', 'gAAAAABoMTYe_vEH1mS8lpYzTmJa4wP65e9GBThMLrxqgxWHKq8ClHM2cjKVKPQJoRFzec9Qp1RqO5ZSO-MGuYPMosPCocZ81w==', '2025-05-23 23:59:42', '2025-05-24 02:59:42');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(80) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(120) NOT NULL,
  `role` enum('admin','doctor','patient') NOT NULL,
  `two_factor_secret` varchar(16) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `phone` varchar(20) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `email`, `role`, `two_factor_secret`, `is_active`, `created_at`, `updated_at`, `phone`) VALUES
(1, 'admin', 'scrypt:32768:8:1$3MrfcEZjsTvpyfAW$d318d6617253c6de531436dcea4a12c11625cfa8226d4c85431369da288af870befe14029281260314226c0235e118787377421e6ae2a1047a1b9441dd0dae57', 'admin@securehealth.com', 'admin', 'UMZGTWP4SEHIFHC6', 1, '2025-05-24 01:22:47', '2025-05-24 02:47:08', '01232192'),
(4, 'ahmed', 'pbkdf2:sha256:600000$XoEMKU4QDjSB1sSI$00b3e59c562cdf5236143ad64c9162fceae2719d99ee99809008a3635a511de7', 'ahmedlordacio@gmail.com', 'doctor', 'UMZGTWP4SEHIFHC6', 1, '2025-05-24 00:53:30', '2025-05-24 02:47:12', '0219302'),
(5, 'mariam', 'pbkdf2:sha256:600000$wIAu2quoPtJImj0U$079832ced0e5646f9dd57da554d84e532eab89615d3072617710008bd23a6b5e', 'mariammostafaamin@gmail.com', 'admin', 'Z2U7W6T6JIBVGJQL', 1, '2025-05-24 01:45:49', '2025-05-24 02:47:15', '02382922'),
(8, 'test', 'pbkdf2:sha256:600000$07pZtezfStXsV786$887329c9f739d2a1ad2be9835fc3a461d78db9d017246a953c97b782be11eacc', 'test@gmail.com', 'patient', 'EKA6B6L7QN25NKSV', 1, '2025-05-24 01:53:05', '2025-05-24 02:47:20', '0314132'),
(9, 'test2', 'pbkdf2:sha256:600000$Icji8Y6eQPVYdspo$9f53ecc64516ba1895a56bfc59de544cd6526c7757e5c81672ad2a619506e3c6', 'test2@gmail.com', 'patient', 'RNDOB5V7RRI2TXQF', 1, '2025-05-24 01:57:02', '2025-05-24 02:47:25', '023812391'),
(10, 'askds', 'pbkdf2:sha256:600000$4BaX9KNOiNTyNQNA$7807f091c34e4e7d960e83848285b1132d3c0c38d38eb779d8fea180da78136b', 'dwd@agmail.com', 'patient', '5LVP4RESOFYG2Q2X', 1, '2025-05-24 02:09:00', '2025-05-24 02:47:28', '023812391'),
(11, 'sadasd', 'pbkdf2:sha256:600000$NkdII7CnLqhmmEHX$ba43aecead96877ba2177a6b1944f2f67d28583a762380ba1cb3511c3bb0ed39', 'sda@gmail.com', 'patient', 'VLGKLMEWMUDI6BYM', 1, '2025-05-24 02:40:40', '2025-05-24 02:47:30', '023812391');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `appointments`
--
ALTER TABLE `appointments`
  ADD PRIMARY KEY (`id`),
  ADD KEY `patient_id` (`patient_id`),
  ADD KEY `doctor_id` (`doctor_id`);

--
-- Indexes for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `patient_records`
--
ALTER TABLE `patient_records`
  ADD PRIMARY KEY (`id`),
  ADD KEY `patient_id` (`patient_id`),
  ADD KEY `doctor_id` (`doctor_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `appointments`
--
ALTER TABLE `appointments`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `audit_logs`
--
ALTER TABLE `audit_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=74;

--
-- AUTO_INCREMENT for table `patient_records`
--
ALTER TABLE `patient_records`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `appointments`
--
ALTER TABLE `appointments`
  ADD CONSTRAINT `appointments_ibfk_1` FOREIGN KEY (`patient_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `appointments_ibfk_2` FOREIGN KEY (`doctor_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `audit_logs`
--
ALTER TABLE `audit_logs`
  ADD CONSTRAINT `audit_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL;

--
-- Constraints for table `patient_records`
--
ALTER TABLE `patient_records`
  ADD CONSTRAINT `patient_records_ibfk_1` FOREIGN KEY (`patient_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `patient_records_ibfk_2` FOREIGN KEY (`doctor_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
